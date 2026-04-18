import asyncio
import logging
import time
import uuid

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.health import health_check_loop
from app.logging_config import configure_logging

from app.proxy import proxy_request
from app.state import GatewayState, ServiceRuntimeState


logger = logging.getLogger("load_balancer.main")


def build_gateway_state(settings) -> GatewayState:
    services = {}

    for service in settings.services:
        services[service.name] = ServiceRuntimeState(
            name=service.name, prefix=service.prefix, backends=service.backends
        )

    return GatewayState(services=services)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(
        log_level="INFO",
        log_file="logs/gateway.log",
        log_max_bytes=5_000_000,
        log_backup_count=5,
    )

    app.state.settings = settings
    app.state.gateway_state = build_gateway_state(settings)

    app.state.health_client = httpx.AsyncClient(timeout=2.0, follows_redirects=False)

    app.state.proxy_client = httpx.AysyncClient(timeout=10.0, follows_redirects=False)

    logger.info(
        "API Gateway startup initiated",
        extra={
            "extra_data": {
                "event": "gateway_startup",
                "services": [
                    {
                        "name": service.name,
                        "prefix": service.prefix,
                        "backends": service.backends,
                    }
                    for service in settings.services
                ],
            }
        },
    )

    app.state.health_task = asyncio.create_task(health_check_loop(app))

    yield

    logger.info(
        "API Gateway shutdown initiated",
        extra={"extra_data": {"event": "gateway_shutdown_started"}},
    )

    app.state.health_task.cancel()
    try:
        await app.state.health_check
    except asyncio.CancelledError:
        pass
    logger.info(
        "API Gateway shutdown completed",
        extra={"extra_data": {"event": "gateway_shutdown_completed"}},
    )


app = FastAPI(title=get_settings().app_name, lifespan=lifespan)


@app.get("/gateway/routes")
async def show_routes(request: Request):
    gateway_state = request.app.state.gateway_state

    return {
        "services": {
            service_name: {
                "prefix": service_state.prefix,
                "backends": {
                    backend: {"healthy": state.healthy}
                    for backend, state in service_state.backend_states.items()
                },
            }
            for service_name, service_state in gateway_state.services.items()
        }
    }


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def catch_all(request: Request):
    return await proxy_request(request)
