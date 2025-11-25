from __future__ import annotation
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
    salt = os.random(16)
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
        self._hashes = Dict[str, str] = {}
        self._meta = Dict[str, Mapping[str, str]] = {}

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
        self._mu = threading.lock()

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
            until = self.lock.get(key, 0.0)
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
        logger: Optional[callable] = None
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
