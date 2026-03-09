from __future__ import annotations
from datetime import datetime, timedelta, timezone
import uuid
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt

from .keys import (
    load_private_key_pem,
    load_public_key_pem,
    build_jwks_from_public_pem,
    KID,
)
from .refresh_store import RefreshTokenStore

router = APIRouter(prefix="/auth", tags=["auth"])

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

refresh_store = RefreshTokenStore()


ISSUER = "http://127.0.0.1:8000/"
AUDIENCE = "api.local"
ALGORITHM = "RS256"
ACCESS_MINUTES = 10
REFRESH_DAYS = 14


PRIVATE_KEY = load_private_key_pem("private.pem")
PUBLIC_PEM = load_public_key_pem("public.pem")
JWKS = build_jwks_from_public_pem(PUBLIC_PEM)


fake_users = {
    "chandan": {
        "id": "user_123",
        "username": "chandan",
        "hashed_password": pwd.hash("password123"),
        "roles": ["admin"],
        "scopes": ["read:me", "read:admin"],
    }
}


class LoginIn(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    refresh_token: str


class RefreshIn(BaseModel):
    refresh_token: str


class LogOutIn(BaseModel):
    refresh_token: str


def _create_access_jwt(user_id: str, roles: List[str], scopes: List[str]) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": user_id,
        "roles": roles,
        "scp": scopes,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_MINUTES)).timestamp()),
        "jti": str(uuid.uuid4()),
    }

    headers = {"kid": KID}

    return jwt.encode(payload, PRIVATE_KEY, algorithm=ALGORITHM, headers=headers)


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn):
    user = fake_users.get(body.username)

    if not user or not pwd.verify(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid Credentials")

    access = _create_access_jwt(user["id"], roles=user["roles"], scopes=user["scopes"])
    refresh = refresh_store.mint(user["id"], ttl_seconds=REFRESH_DAYS * 24 * 3600)

    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}


@router.post("/refresh", response_model=TokenOut)
def refresh(body: RefreshIn):
    try:
        sess = refresh_store.validate(body.refresh_token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user = next((u for u in fake_users.values() if u["id"] == sess.user_id), None)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_refresh = refresh_store.rotate(
        body.refresh_token, ttl_seconds=REFRESH_DAYS * 24 * 3600
    )

    access = _create_access_jwt(user["id"], roles=user["roles"], scopes=user["scopes"])

    return {
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


@router.post("/logout")
def logout(body: LogOutIn):
    refresh_store.revoke(body.refresh_token)
    return {"ok": True}


@router.get("/.well-known/jwks.json")
def jwks():
    return JWKS
