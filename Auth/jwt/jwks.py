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
