from __future__ import annotations
import base64
from pathlib import Path
from typing import Dict, Any


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KID = "key-2026-01"


def _b64url_uint(val: int) -> str:
    b = val.to_bytes((val.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def load_private_key_pem(path="private.pem") -> str:
    return Path(path).read_text(encoding="utf-8")


def load_public_key_pem(path="public.pem") -> str:
    return Path(path).read_text(encoding="utf-8")


def build_jwks_from_public_pem(public_pem: str) -> Dict[str, Any]:
    pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
    if not isinstance(pub, rsa.RSAPublicKey):
        raise RuntimeError("Expected RSA public key")

    numbers = pub.public_numbers()

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": KID,
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }

    return {"keys": [jwk]}
