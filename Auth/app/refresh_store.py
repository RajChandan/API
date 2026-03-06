from __future__ import annotations
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass
class RefreshSession:
    user_id: str
    expires_at: int
    revoked: bool = False
    rotation_counter: int = 0


class RefreshTokenStore:
    def __init__(self):
        self._store: Dict[str, RefreshSession] = {}

    def mint(self, user_id: str, ttl_seconds: int) -> str:
        raw = secrets.token_urlsafe(48)
        h = _hash_token(raw)
        print(
            f"Minting refresh token for user_id={user_id}, ttl_seconds={ttl_seconds}, raw={raw}, hash={h}"
        )

        self._store[h] = RefreshSession(
            user_id=user_id,
            expires_at=int(time.time()) + ttl_seconds,
            revoked=False,
            rotation_counter=0,
        )

        return raw
