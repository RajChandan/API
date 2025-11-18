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
