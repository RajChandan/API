from __future__ import annotations
from typing import Dict, Any, Optional, List, Sequence, Set

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import JWTAuthSettings
from .errors import AuthError
from .jwks import JWKSClient
from .utils import parse_bearer
from .verify import verify_access_token


class JWTAuth:
    def __init__(self, settings: JWTAuthSettings):
        self.settings = settings
        self._bearer = HTTPBearer(auto_error=False)

        self.jwks = (
            JWKSClient(
                settings.jwks_url or "",
                ttl_seconds=settings.jwks_cache_ttl_seconds,
                timeout_seconds=settings.jwks_timeout_seconds,
            )
            if settings.jwks_url
            else None
        )

    def _http(self, e: AuthError) -> None:
        raise HTTPException(status_code=e.status_code, detail=e.detail)

    async def current_user(
        self,
        request: Request,
        creds: Optional[HTTPAuthorizationCredentials] = Depends(
            HTTPBearer(auto_error=False)
        ),
    ) -> Dict[str, Any]:
        try:
            token = None
            auth_header = request.headers.get("Authorization")
            token = parse_bearer(auth_header)

            if not token and self.settings.accept_token_in_query_param:
                token = request.query_params.get("access_token")

            if not token:
                raise AuthError("Missing token", status_code=401, code="token_missing")

            return await verify_access_token(
                token, self.settings, jwks_client=self.jwks
            )

        except AuthError as e:
            self._http(e)

    def require_scopes(self, required: Sequence[str]):
        required_set = Set[str] = set(required)

        async def _dep(
            user: Dict[str, Any] = Depends(self.current_user),
        ) -> Dict[str, Any]:
            scopes = set(user.get("_scopes") or [])
            if not required_set.issubset(scopes):
                raise HTTPException(status_code=403, detail="Forbidden")
            return user

        return _dep

    def require_roles(self, required: Sequence[str]):
        required_set: Set[str] = set(required)

        async def _dep(
            user: Dict[str, Any] = Depends(self.current_user),
        ) -> Dict[str, Any]:
            roles = set(user.get("_roles") or [])
            if not (roles and required_set.issubset(roles)):
                raise HTTPException(status_code=403, detail="Forbidden")
            return user

        return _dep
