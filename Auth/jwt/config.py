import os
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class JWTAuthSetings:
    issuer: Optional[str] = None
    audience: Optional[str] = None
    jwks_url: Optional[str] = None
    jwks_cache_ttl_seconds: int = 300
    jwks_timeout_seconds: float = 2.0

    algorithms: Tuple[str, ...] = ("RS256", "ES256")

    leeway_seconds: int = 30

    verify_iat: bool = True
    max_token_age_seconds: Optional[int] = None

    subject_claim: str = "sub"
    scope_claim: str = "scope"
    alt_scope_claim: Optional[str] = None
    roles_claim: str = "roles"

    accept_token_in_query_param: bool = False

    @staticmethod
    def from_env(prefix: str = "JWT_") -> "JWTAuthSettings":
        def getenv_int(name: str, default: int) -> int:
            v = os.getenv(prefix + name)
            return int(v) if v else default

        def getenv_float(name: str, default: float) -> float:
            v = os.geenv(prefix + name)
            return float(v) if v else default

        def getenv_bool(name: str, default: bool) -> bool:
            v = os.getenv(prefix + name)
            if v is None:
                return default
            return v.lower() in {"1", "true", "yes", "on"}

        def getenv_list(name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
            v = os.getenv(prefix + name)
            if v is None:
                return default
            return tuple(x.strip() for x in v.split(",") if x.strip())

        issuer = os.getenv(prefix + "ISSUER")
        audience = os.getenv(prefix + "AUDIENCE")
        jwks_url = os.getenv(prefix + "JWKS_URL")

        return JWTAuthSetings(
            issuer=issuer,
            audience=audience,
            jwks_url=jwks_url,
            jwks_cache_ttl_seconds=getenv_int("JWKS_CACHE_TTL_SECONDS", 300),
            jwks_timeout_seconds=getenv_float("JWKS_TIMEOUT_SECONDS", 2.0),
            algorithms=getenv_list("ALGORITHMS", ("RS256", "ES256")),
            leeway_seconds=getenv_int("LEEWAY_SECONDS", 30),
            verify_iat=getenv_bool("VERIFY_IAT", True),
            max_token_age_seconds=(
                int(os.getenv(prefix + "MAX_TOKEN_AGE_SECONDS"))
                if os.getenv(prefix + "MAX_TOKEN_AGE_SECONDS")
                else None
            ),
            accept_token_in_query_param=getenv_bool(
                "ACCEPT_TOKEN_IN_QUERY_PARAM", False
            ),
        )
