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
