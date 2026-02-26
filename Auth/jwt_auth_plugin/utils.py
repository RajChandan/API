from __future__ import annotations
from typing import Any, List, Optional


def parse_bearer(authorization_header: Optional[str]) -> Optional[str]:
    if not authorization_header:
        return None

    parts = authorization_header.split()
    if len(parts) != 2:
        return None

    if parts[0].lower() != "bearer":
        return None

    return parts[1].strip()


def normalize_scopes(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [s for s in value.split() if s]

    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]


def normalize_roles(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [r.strip() for r in value.split(",") if r.strip()]

    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]

    return []
