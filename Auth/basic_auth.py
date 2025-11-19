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
