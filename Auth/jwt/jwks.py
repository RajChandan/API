from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, Optional
import time
import httpx

from .errors import AuthError


@dataclass
class _CacheEntry:
    jwks: Dict[str, Any]
    expires_at: float


class JWKSClient:
    def __init__(
        self, jwks_url: str, ttl_seconds: int = 300, timeout_seconds: float = 2.0
    ):
        if not jwks_url:
            raise ValueError("JWKS URL must be provided")

        self.jwk_url = jwks_url
        self.ttl_seconds = max(10, int(ttl_seconds))
        self.timeout_seconds = float(timeout_seconds)
        self._cache: Optional[_CacheEntry] = None

    async def get_jwks(self, force_refresh: bool = False) -> Dict[str, Any]:
        now = time.time()
        if not force_refresh and self._cache and self._cache.expires_at > now:
            return self._cache.jwks

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                resp = await client.get(
                    self.jwks_url, headers={"Accept": "application/json"}
                )
                resp.raise_for_status()
                jwks = resp.json()
            if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
                raise AuthError(
                    detail="Invalid JWKS response", status_code=401, code="jwks_invalid"
                )
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            if (
                self._cache
                and isinstance(self._cache.jwks.get("keys"), list)
                and self._cache.jwks["keys"]
            ):
                return self._cache.jwks
            raise AuthError(
                "Unable to fetch public keys", status_code=401, code="jwks_fetch_failed"
            )
        self._cache = _CacheEntry(jwks=jwks, expires_at=now + self.ttl_seconds)
        return jwks

    @staticmethod
    def find_key(jwks: Dict[str, Any], kid: Optional[str]) -> Optional[Dict[str, Any]]:
        keys = jwks.get("keys") or []
        if not keys:
            return None

        if not kid:
            return keys[0] if len(keys) == 1 else None

        for k in keys:
            if k.get("kid") == kid:
                return k
        return None
