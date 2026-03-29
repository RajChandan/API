from functools import lru_cache
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensetive=False
    )
    app_name: str = "Load Balancer"
    app_host: str = "0.0.0.0"
    app_port: int = 8080
    log_level: str = "INFO"
    log_file: str = "logs/app.log"
    log_max_bytes: int = 5_000_000
    log_backup_count: int = 5

    backends: List[str] = Field(
        default=[
            "http://127.0.0.1:9001",
            "http://127.0.0.1:9002",
            "http://127.0.0.1:9003",
        ]
    )

    health_check_interval: int = 5

    health_check_connect_timeout: float = 2.0
    health_check_read_timeout: float = 2.0
    health_check_write_timeout: float = 2.0
    health_check_pool_timeout: float = 2.0

    # health_check_timeout: float = 2.0

    proxy_connect_timeout: float = 3.0
    proxy_read_timeout: float = 10.0
    proxy_write_timeout: float = 10.0
    proxy_pool_timeout: float = 5.0

    health_max_connections: int = 20
    health_max_keepalive_connections: int = 10

    proxy_max_connections: int = 200
    proxy_max_keepalive_connections: int = 50

    @field_validator("backends")
    @classmethod
    def validate_backends(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("Atleast one backend must be configured")

        cleaned = []
        for backend in value:
            backend = backend.strip().rstrip("/")
            if not backend.startswith(("http://", "https://")):
                raise ValueError(
                    f"invalid backend '{backend}'. Must start with http:// or https://"
                )
            cleaned.append(backend)
        return cleaned

    @field_validator("health_check_interval")
    @classmethod
    def validate_health_check_interval(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("health_check_interval must be greater than 0")
        return value

    @field_validator(
        "log_max_bytes",
        "log_backup_count",
        "health_max_connections",
        "health_max_keepalive_connections",
        "proxy_max_connections",
        "proxy_max_keepalive_connections",
    )
    @classmethod
    def validate_timeouts(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("Timeout Values must be greater that 0")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log level must be in {allowed}")
        return upper

    @field_validator("log_max_bytes", "log_backup_count")
    @classmethod
    def validate_log_rotation(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Must be greater that 0")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
