from __future__ import annotations
from typing import Dict, Any, Optional, List, Sequence, Set

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import JWTAuthSetings
from .errors import AuthError
from .jwks import JWKSClient
from .utils import parse_bearer
from .verify import verify_access_token
