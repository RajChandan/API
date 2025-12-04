from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import os
import threading
import time
from dataclasses import dataclass
from typing import (
    Dict,
    Iterable,
    Mapping,
    MutableMapping,
    Optional,
    Protocol,
    Tuple,
    Set,
)
from fastapi import Request, Response, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import bcrypt


def _scrypt_hash(password: str, *, n: int = 2**14, r: int = 8, p: int = 1) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return "scrypt$" + base64.b64encode(salt + dk).decode()


def _scrypt_verify(password: str, hashed: str) -> bool:
    try:
        blob = base64.b64decode(hashed.split("$", 1)[1])
        salt, dk = blob[:16], blob[16:]
        test = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, test)
    except Exception:
        return False


def hash_password(password: str) -> str:
    if bcrypt:
        salt = bcrypt.gensalt(rounds=12)
        return "bcrypt$" + bcrypt.hashpw(password.encode(), salt).decode()
    return _scrypt_hash(password)


def verify_password(password: str, hashed: str) -> bool:
    if hashed.startswith("bcrypt$") and bcrypt:
        real = hashed.split("$", 1)[1].encode()
        try:
            return bcrypt.checkpw(password.encode(), real)
        except Exception:
            return False
    if hashed.startswith("scrypt$"):
        return _scrypt_verify(password, hashed)
    if bcrypt and hashed.startswith("$2b$"):
        try:
            return bcrypt.checkpw(password.encode(), hashed.encode())
        except Exception:
            return False
    return False


class UserStore(Protocol):
    def get_hash(self, username: str) -> Optional[str]: ...

    def get_metadata(self, username: str) -> Mapping[str, str]:
        return {}


class InMemoryUserStore:
    def __init__(
        self, users: Mapping[str, str] | Mapping[str, Tuple[str, Mapping[str, str]]]
    ):
        self._hashes: Dict[str, str] = {}
        self._meta: Dict[str, Mapping[str, str]] = {}

        for u, v in users.items():
            if isinstance(v, tuple):
                h, meta = v
                self._hashes[u] = h
                self._meta[u] = meta
            else:
                self._hashes[u] = v

    def get_hash(self, username: str) -> Optional[str]:
        return self._hashes.get(username)

    def get_metadata(self, username: str) -> Mapping[str, str]:
        return self._meta.get(username, {})


class EnvUserStore:
    def __init__(self, var_name: str = "Basic_Auth"):
        raw = os.getenv(var_name, "")
        users: Dict[str, str] = {}
        if raw:
            for pair in raw.split(","):
                if ":" in pair:
                    u, h = pair.split(":", 1)
                    users[u.strip()] = h.strip()
        self._inner = InMemoryUserStore(users)

    def get_hash(self, username: str) -> Optional[str]:
        return self._inner.get_hash(username)

    def get_metadata(self, username: str) -> Mapping[str, str]:
        return self._inner.get_metadata(username)


@dataclass
class _Counter:
    attempts: int
    reset_at: float


class _Throttle:
    def __init__(self):
        self._rl: Dict[str, _Counter] = {}
        self._lock: Dict[str, float] = {}
        self._mu = threading.Lock()

    def check_rate(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        with self._mu:
            c = self._rl.get(key)
            if not c or c.reset_at < now:
                self._rl[key] = _Counter(1, now + window)
                return True
            if c.attempts < limit:
                c.attempts += 1
                return True
            return False

    def lock(self, key: str, seconds: int) -> None:
        with self._mu:
            self._lock[key] = max(self._lock.get(key, 0.0), time.time() + seconds)

    def is_locked(self, key: str) -> bool:
        with self._mu:
            until = self._lock.get(key, 0.0)
            if until <= time.time():
                if key in self._lock:
                    del self._lock[key]
                return False
            return True


class BasicAuth:
    def __init__(
        self,
        *,
        realm: str = "Restricted",
        user_store: UserStore,
        require_https: bool = True,
        allow_plain_http_from_localhost: bool = True,
        ip_allowlist: Optional[Iterable[str]] = None,
        ip_blocklist: Optional[Iterable[str]] = None,
        rate_limit_attempts: int = 20,
        rate_limit_window_seconds: int = 60,
        lockout_after_attempts: int = 5,
        lockout_seconds: int = 15 * 60,
        logger: Optional[callable] = None,
    ) -> None:
        self.realm = realm
        self.user_store = user_store
        self.require_https = require_https
        self.allow_plain_http_from_localhost = allow_plain_http_from_localhost
        self.rate_limit_attempts = rate_limit_attempts
        self.rate_limit_window_seconds = rate_limit_window_seconds
        self.lockout_after_attempts = lockout_after_attempts
        self.lockout_seconds = lockout_seconds
        self.logger = logger
        self._throttle = _Throttle()
        self._ip_allow: Set[ipaddress._BaseNetwork] = set()
        self._ip_block: Set[ipaddress._BaseNetwork] = set()

        for lst, target in (
            (ip_allowlist, self._ip_allow),
            (ip_blocklist, self._ip_block),
        ):
            if lst:
                for net in lst:
                    target.add(ipaddress.ip_network(net, strict=False))
        self._security = HTTPBasic(auto_error=False)
        print("BasicAuth initialized")

    async def __call__(
        self, request: Request, credentials: HTTPBasicCredentials = None
    ) -> Mapping[str, str]:
        credentials = await self._security(request)
        print("BasicAuth __call__ invoked")
        if not credentials:
            print("No credentials provided")
            credentials = await self._security(request)
            # raise HTTPException(
            #     status_code=status.HTTP_401_UNAUTHORIZED,
            #     detail="Unauthorized",
            #     headers={"WWW-Authenticate": f'Basic realm="{self.realm}"'},
            # )
        username = credentials.username if credentials else None
        password = credentials.password if credentials else None
        client_ip = self._client_ip_from_request(request)
        is_https = self._is_https_request(request)
        headers = {k.lower(): v for k, v in request.headers.items()}
        print(headers, " === HEADERS")
        return self._verify(
            scope_headers=headers,
            client_ip=client_ip,
            username=username or "",
            password=password or "",
            is_https=is_https,
        )

    @staticmethod
    def _client_ip_from_request(request: Request) -> str:
        xff = request.headers.get("X-Forwarded-For")
        print(xff, " === XFF")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else "0.0.0.0"

    @staticmethod
    def _is_https_request(request: Request) -> bool:
        if request.url.scheme == "https":
            return True
        return request.headers.get("X-Forwarded-Proto") == "https"

    def _ip_allowed(self, ip: str) -> bool:
        ip = ipaddress.ip_address(ip)
        if self._ip_allow and not any(ip in net for net in self._ip_allow):
            return False
        if self._ip_block and any(ip in net for net in self._ip_block):
            return False
        return True

    def _unauthorized(self) -> HTTPException:
        headers = {
            "WWW-Authenticate": f"Basic realm={self.realm}",
            "charset": "UTF-8",
        }
        return HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers=headers,
        )

    def _verify(
        self,
        *,
        scope_headers: Mapping[str, str],
        client_ip: str,
        username: str,
        password: str,
        is_https: bool,
    ) -> Mapping[str, str]:
        print(f"Verifying Basic Auth : {client_ip} - {username}")
        if self.require_https and not is_https:
            if not (
                self.allow_plain_http_from_localhost
                and client_ip in {"127.0.0.1", "::1"}
            ):
                raise self._unauthorized()

        if not self._ip_allowed(client_ip):
            print(f"IP {client_ip} is not allowed")
            raise self._unauthorized()

        if not username or not password:
            print(f"Missing username or password")
            raise self._unauthorized()

        rl_key = f"rl:{client_ip}:{username}"
        print(rl_key, " === Rate Limit Key")
        if not self._throttle.check_rate(
            rl_key, self.rate_limit_attempts, self.rate_limit_window_seconds
        ):
            print(f"Rate limit exceeded for {rl_key}")
            raise self._unauthorized()

        lock_key = f"lock:{client_ip}:{username}"
        if self._throttle.is_locked(lock_key):
            raise self._unauthorized()

        stored = self.user_store.get_hash(username)
        if not stored or not verify_password(password, stored):
            if self.lockout_after_attempts <= 1:
                self._throttle.lock(lock_key, self.lockout_seconds)
            raise self._unauthorized()

        print(f"User {username} authenticated successfully from IP {client_ip}")
        return {
            "username": username,
            "ip": client_ip,
            "metadata": self.user_store.get_metadata(username),
            "auth_scheme": "basic",
            "realm": self.realm,
        }


class BasicAuthMiddleware:
    def __init__(
        self,
        app,
        *,
        authenticator: BasicAuth,
        protected_prefix: str = "/",
        exempt_path: Optional[Iterable[str]] = None,
    ):
        self.app = app
        self.authenticator = authenticator
        self.prefix = protected_prefix.rstrip("/") or "/"
        self.exempt: Set[str] = set(exempt_path or [])
        print("BasicAUTH Middleware initialized")

    async def __call__(self, scope, receive, send):
        print(f"Scope received in Middleware: {scope}")
        if scope["type"] != "http":
            print("Non-HTTP request, passing through")
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        print(path, " === Request Path")
        if any(path == e or path.startswith(e.rstrip("/") + "/") for e in self.exempt):
            print(f"Path {path} is exempted, passing through")
            return await self.app(scope, receive, send)

        if (
            self.prefix == "/"
            or path == self.prefix
            or path.startswith(self.prefix + "/")
        ):
            headers = {
                k.decode().lower(): v.decode() for k, v in scope.get("headers", [])
            }
            print(headers, " === MIDDLEWARE HEADERS")
            client_ip = (scope.get("client") or (None,))[0] or "0.0.0.0"
            xff = headers.get("x-forwarded-for")
            print(xff, " === XFF in Middleware")
            if xff:
                client_ip = xff.split(",")[0].strip()
            is_https = (
                scope.get("scheme") == "https"
                or headers.get("x-forwarded-proto") == "https"
            )

            auth = headers.get("authorization")
            print(auth, " === Authorization Header")
            if not auth or not auth.startswith("Basic"):
                print("Missing or invalid Authorization header")
                headers_out = [
                    (
                        b"www-authenticate",
                        f'Basic realm="{self.authenticator.realm}", charset="UTF-8"'.encode(),
                    )
                ]
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": headers_out,
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"Unauthorized",
                        "more_body": False,
                    }
                )
                return
            try:
                raw = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
                username, password = raw.split(":", 1)
            except Exception:
                headers_out = [
                    (
                        b"www-authenticate",
                        f'Basic realm="{self.authenticator.realm}", charset="UTF-8"'.encode(),
                    )
                ]
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": headers_out,
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"Unauthorized",
                        "more_body": False,
                    }
                )
                return

            try:
                user = self.authenticator._verify(
                    scope_headers=headers,
                    client_ip=client_ip,
                    username=username or "",
                    password=password or "",
                    is_https=is_https,
                )
                print(f"scope {scope} , receive :{receive} , send :{send}")
                scope["state"]["user"] = user
                return await self.app(scope, receive, send)
            except HTTPException as exc:
                headers_out = (
                    [(k.encode(), v.encode()) for k, v in exc.headers.items()]
                    if exc.headers
                    else []
                )
                print(headers_out, " === Unauthorized Headers")
                await send(
                    {
                        "type": "http.response.start",
                        "status": exc.status_code,
                        "headers": headers_out,
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b"Unauthorized",
                        "more_body": False,
                    }
                )
                return
        return await self.app(scope, receive, send)


__all__ = [
    "BasicAuth",
    "BasicAuthMiddleware",
    "UserStore",
    "InMemoryUserStore",
    "EnvUserStore",
    "hash_password",
    "verify_password",
]
