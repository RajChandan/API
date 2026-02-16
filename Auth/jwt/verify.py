from __future__ import annotations
from typing import Any, Dict, Optional
import base64, json, time

from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError

from .config import JWTAuthSetings
from .errors import AuthError
from .jwks import JWKSClient
from .utils import normalize_roles, normalize_scopes


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def peek_header(token: str) -> Dict[str, Any]:
    try:
        header_b64 = token.split(".")[0]
        return json.loads(_b64url_decode(header_b64).decode("utf-8"))
    except Exception:
        return {}


async def verify_jwt(
    token: str, settings: JWTAuthSetings, jwks_client: Optional[JWKSClient] = None
) -> Dict[str, Any]:
    if not token or "." not in token:
        raise AuthError("Missing Token", status_code=401, code="token_missing")

    header = peek_header(token)
    kid = header.get("kid")
    alg = header.get("alg")

    if alg and alg not in settings.algorithms:
        raise AuthError(
            "Unsupported token algorithm", status_code=401, code="alg_not_allowed"
        )

    if not settings.jwks_url:
        raise AuthError(
            "Server Auth not configured (JWKS_URL missing)",
            status_code=500,
            code="jwks_not_configured",
        )

    if jwks_client is None:
        jwks_client = JWKSClient(
            settings.jwks_url,
            ttl_seconds=settings.jwks_cache_ttl_seconds,
            timeout_seconds=settings.jwks_timeout_seconds,
        )

    jwks = await jwks_client.get_jwks(force_refresh=False)

    jwk = jwks_client.find_key(jwks, kid)

    if not jwk:
        jwks = await jwks_client.get_jwks(force_refresh=True)
        jwk = jwks_client.find_key(jwks, kid)

    if not jwk:
        raise AuthError("Unknown signing key", status_code=401, code="key_not_found")

    options = {
        "verify_aud": bool(settings.audience),
        "verify_iss": bool(settings.issuer),
        "verify_iat": bool(settings.verify_iat),
    }

    try:
        payload = jwt.decode(
            token,
            jwk,
            algorithms=list(settings.algorithms),
            audience=settings.audience,
            issuer=settings.issuer,
            options=options,
            leeway=settings.leeway_seconds,
        )

    except ExpiredSignatureError:
        raise AuthError("Token Expired", status_code=401, code="token_expired")

    except JWTClaimsError:
        raise AuthError("Invalid token claims", status_code=401, code="invalid_claims")

    except JWTError:
        raise AuthError("Invalid token", status_code=401, code="token_invalid")

    if settings.max_token_age_seconds is not None:
        iat = payload.get("iat")
        if not isinstance(iat, (int, float)):
            raise AuthError("Invalid iat claim", status_code=401, code="invalid_iat")

        if int(time.time()) - int(iat) > int(settings.max_token_age_seconds):
            raise AuthError("Token is too old", status_code=401, code="token_too_old")

        scopes = normalize_scopes(
            payload.get(settings.scope_claim)
        ) or normalize_scopes(payload.get(settings.alt_scope_claim))

        roles = normalize_roles(payload.get(settings.roles_claim))

        payload["_scopes"] = scopes
        payload["_roles"] = roles

        print(f"Token scopes: {scopes}, roles: {roles} , payload: {payload}")
        return payload
