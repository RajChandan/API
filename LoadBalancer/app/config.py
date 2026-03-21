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

    backends: List[str] = Field(
        default=[
            "http://127.0.0.1:9001",
            "http://127.0.0.1:9002",
            "http://127.0.0.1:9003",
        ]
    )

    health_check_interval: int = 5
    health_check_timeout: float = 2.0
    proxy_timeout: float = 10.0

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

    @field_validator("health_check_timeout", "proxy_timeout")
    @classmethod
    def validate_timeouts(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("Timeout Values must be greater that 0")
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
