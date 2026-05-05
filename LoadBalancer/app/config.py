from functools import lru_cache
from pathlib import Path
import yaml
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServicePolicy(BaseModel):
    allowed_methods: List[str] = Field(
        default=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    )
    require_auth: bool = False
    strip_prefix: bool = True
    max_request_body_bytes: int = 1_048_576

    connect_timeout: float = 3.0
    read_timeout: float = 10.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    retry_enabled: bool = True
    retry_max_attempts: int = 2
    retry_backoff_ms: int = 200
    retry_on_methods: List[str] = Field(default=["GET", "HEAD", "OPTIONS"])

    circuit_breaker_enabled: bool = True
    circuit_breaker_failure_threshold: int = 3
    circuit_breaker_ejection_seconds: int = 30

    rate_limit_enabled: bool = True
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    required_roles : List[str] = Field(default=[])
    required_scopes : List[str] = Field(default=[])

    @field_validator("allowed_methods","retry_on_methods")
    @classmethod
    def validate_allowed_methods(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("allowed_methods must not be empty")

        allowed = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
        normalized = []
        seen = set()

        for method in value:
            method = method.upper().strip()

            if method not in allowed:
                raise ValueError(f"Unsupported HTTP method : {method}")
            
            if method not in seen:
                normalized.append(method)
                seen.add(method)        
        return normalized
        
    @field_validator("connect_timeout", "read_timeout", "write_timeout", "pool_timeout")
    @classmethod
    def validate_timeouts(cls, value: float) -> float:
        if value <= 0:
            raise ValueError("Timeout value must be greater than 0")
        return value

    @field_validator("max_request_body_bytes","retry_max_attempts","retry_backoff_ms","circuit_breaker_failure_threshold","circuit_breaker_ejection_seconds")
    @classmethod
    def validate_positive_ints(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Value must be greater than 0")
        return value

    
    @field_validator("rate_limit_requests","rate_limit_window_seconds")
    @classmethod
    def validate_rate_limit_ints(cls,value:int) -> int:
        if value <= 0:
            raise ValueError("Rate limit value must be greater than 0")
        return value




class ServiceConfig(BaseModel):
    name: str
    prefix: str
    backends: List[str]
    policy: ServicePolicy = Field(default_factory=ServicePolicy)

    @field_validator("prefix")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("Service prefix must start with '/'")
        return value.rstrip("/") or "/"

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


class GatewayConfig(BaseModel):
    services: List[ServiceConfig]

    @field_validator("services")
    @classmethod
    def validate_services(cls,value:List[ServiceConfig]) -> List[ServiceConfig]:
        if not value:
            raise ValueError("At least one service must be configured")
        names = set()
        prefixes = set()
        for service in value:
            if service.name in names:
                raise ValueError(f"Duplicate service name : {service.name} ")
            names.add(service.name)

            if service.prefix in prefixes:
                raise ValueError(f"Duplicate service prefix : {service.prefix}")
            prefixes.add(service.prefix)

        return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )
    app_name: str = "API Gateway"
    app_host: str = "0.0.0.0"
    app_port: int = 8080
    gateway_config_file : str = "app/gateway.yaml"
    
    admin_token: str = "super-secret-admin-token"

    jwt_secret_key: str = "dev-secret-change-me"
    jwt_algorithm: str = "HS256"

    redis_url : str = "redis://127.0.0.1:6379/0"

def load_gateway_config(config_file:str) -> GatewayConfig:
    path = Path(config_file)

    if not path.exists():
        raise FileNotFoundError(f"Gateway config file not found : {config_file}")
    
    with path.open("r",encoding="utf-8") as file:
        raw_config = yaml.safe_load(file)

    if not raw_config:
        raise ValueError(f"Gateway config file is empty : {config_file}")

    return GatewayConfig(**raw_config)

@lru_cache
def get_settings() -> Settings:
    return Settings()

@lru_cache
def get_gateway_config() -> GatewayConfig:
    settings = get_settings()
    return load_gateway_config(settings.gateway_config_file)

