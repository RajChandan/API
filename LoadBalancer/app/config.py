from functools import lru_cache
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServicePolicy(BaseModel):
    allowed_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    )
    require_auth: bool = False
    max_request_body_bytes: int = 1_048_576

    connect_timeout: float = 3.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0

    @field_validator("allowed_methods")
    @classmethod
    def validate_allowed_methods(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("allowed_methods must not be empty")

        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

        normalized = [method.upper().strip() for method in value]

        for method in normalized:
            if method not in allowed:
                raise ValueError(f"Unsupported HTTP method : {method}")
        return normalized

    @field_validator("connect_timeout", "read_timeout", "write_timeout", "pool_timeout")
    @classmethod
    def validate_timeouts(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("Timeout value must be greater than 0")
        return value

    @field_validator("max_request_body_bytes")
    @classmethod
    def validate_body_limit(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("max_request_body_bytes must be greater than 0")
        return value


class ServiceConfig(BaseModel):
    name: str
    prefix: str
    backends: List[str]
    policy: ServicePolicy = Field(defult_factory=ServicePolicy)

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("Service prefix must start with '/'")
        return value.rstrip("/")

    @field_validator("backends")
    @classmethod
    def validate_backends(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("At least one backend must be configured for each service")

        cleaned = []
        for backend in value:
            backend = backend.strip().rstrip("/")
            if not backend.startswith(("http://", "https://")):
                raise ValueError(
                    f"Invalid backend '{backend}' in service config. Must start with http:// or https://"
                )
            cleaned.append(backend)

        return cleaned


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensetive=False,extra="ignore"
    )
    app_name: str = "API Gateway"
    app_host: str = "0.0.0.0"
    app_port: int = 8080
    gateway_api_key : Optional[str] = "super-secret-gateway-key"
    services: List[ServiceConfig] = Field(
        default=[
            ServiceConfig(
                name="user-service",
                prefix="/users",
                backends=[
                    "http://127.0.0.1:9001",
                    "http://127.0.0.1:9002",
                ],
                policy=ServicePolicy(
                    allowed_methods=["GET", "POST"],
                    require_auth=False,
                    max_request_body_bytes=512_000,
                    connect_timeout=2.0,
                    read_timeout=5.0,
                    write_timeout=5.0,
                    pool_timeout=3.0,
                ),
            ),
            ServiceConfig(
                name="order-service",
                prefix="/orders",
                backends=[
                    "http://127.0.0.1:9011",
                    "http://127.0.0.1:9012",
                ],
                policy=ServicePolicy(
                    allowed_methods=["GET", "POST", "DELETE"],
                    require_auth=True,
                    max_request_body_bytes=1_048_576,
                    connect_timeout=3.0,
                    read_timeout=10.0,
                    write_timeout=10.0,
                    pool_timeout=5.0,
                ),
            ),
        ]
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
    