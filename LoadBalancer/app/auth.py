from typing import Any, Dict, Optional

import jwt
from fastapi import Request


class AuthError(Exception):
    pass


def authorize_payload(payload:Dict[str,Any],required_roles:list[str],required_scopes:list[str]) -> None:
    token_roles = payload.get("roles",[])
    token_scopes = payload.get("scopes",[])

    if isinstance(token_roles,str):
        token_roles = [token_roles]

    if isinstance(token_scopes,str):
        token_scopes = token_scopes.split()

    missing_roles = [role for role in required_roles if role not in token_roles]

    missing_scopes = [scope for scope in required_scopes if scope not in token_scopes]

    if missing_roles:
        raise AuthError(f"Missing required roles : {missing_roles}")
    
    if missing_scopes:
        raise AuthError(f"missing required scopes: {missing_scopes}")
    


def extract_bearer_token(request: Request) -> Optional[str]:
    auth_header = request.headers.get("authorization")

    if not auth_header:
        return None

    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise AuthError("Invalid Authorization header format")

    return parts[1]


def verify_jwt_token(token: str, secret_key: str, algorithm: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired")

    except jwt.InvalidTokenError:
        raise AuthError("Invalid token")


def authenticate_request(request: Request) -> Dict[str, Any]:
    settings = request.app.state.settings

    token = extract_bearer_token(request)
    if not token:
        raise AuthError("Missing bearer token")

    return verify_jwt_token(
        token=token,
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


def build_identity_headers(payload: Dict[str, Any]) -> Dict[str, str]:
    headers = {}
    user_id = payload.get("sub")
    roles = payload.get("roles")

    if user_id:
        headers["X-User_ID"] = str(user_id)

    if roles:
        if isinstance(roles, list):
            headers["X-User_Roles"] = ",".join(str(role) for role in roles)

        else:
            headers["X-User-Roles"] = str(roles)

    return headers
