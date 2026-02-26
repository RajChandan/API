from __future__ import annotations


class AuthError(Exception):
    def __init__(
        self,
        detail: str = "Unauthorized",
        status_code: int = 401,
        code: str = "unauthorized",
    ):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.code = code
