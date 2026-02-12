from __future__ import annotations
from typing import Any, Dict, Optional
import base64, json, time

from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatareError, JWTClaimsError

from .config import JWTAuthSetings
from .errors import AuthError
from .jwks import JWKSClient
from .utils import normalize_roles, normalize_scopes


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)
