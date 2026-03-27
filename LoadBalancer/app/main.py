import asyncio
import logging
import time
import uuid

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request

from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.health import health_check_loop
from app.logging_config import configure_logging
from app.proxy import proxy_request
from app.state import LoadBalancerState


logger = logging.getLogger("load_balancer.main")


class RequestContextLoggingmiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        logger.info(
            "Incoming request received",
            extra={
                "extra_data": {
                    "event": "incoming_request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "query": str(request.query_params),
                    "client_ip": request.client.host if request.client else None,
                    "user_agent": request.headers.get("user-agent"),
                }
            },
        )
        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response.headers["X-Request_ID"] = request_id
            logger.info(
                "Incoming request received",
                extra={
                    "extra_data": {
                        "event": "incoming_request",
                        "request_id": request_id,
                        "method": request.method,
                        "path": request.url.path,
                        "query": str(request.query_params),
                        "client_ip": request.client.host if request.client else None,
                        "user_agent": request.headers.get("user-agent"),
                    }
                },
            )
            return response

        except Exception:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.exception(
                "Unhandled request error",
                extra={
                    "extra_data": {
                        "event": "request_unhandled_error",
                        "request_id": request_id,
                        "method": request.method,
                        "path": request.url.path,
                        "duration_ms": duration_ms,
                    }
                },
            )
            raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)

    app.state.settings = settings
    app.state.lb_state = LoadBalancerState(backends=settings.backends)

    logger.info(
        "Application startup initiated",
        extra={
            "extra_data": {
                "event": "app_startup",
                "app_name": settings.app_name,
                "log_level": settings.log_level,
                "backends": settings.backends,
                "proxy_timeout": settings.proxy_timeout,
                "health_check_interval": settings.health_check_interval,
                "health_check_timeout": settings.health_check_timeout,
            }
        },
    )

    app.state.health_client = httpx.AsyncClient()
    app.state.proxy_client = httpx.AsyncClient(timeout=settings.proxy_timeout)

    app.state.health_task = asyncio.create_task(health_check_loop(app))

    yield

    logger.info(
        "Application shutdown initiated",
        extra={
            "extra_data": {
                "event": "app_shutdown_started",
            }
        },
    )

    app.state.health_task.cancel()
    try:
        await app.state.health_task
    except asyncio.CancelledError:
        pass

    await app.state.health_client.aclose()
    await app.state.proxy_client.aclose()

    logger.info(
        "Application shutdown completed",
        extra={
            "extra_data": {
                "event": "app_shutdown_completed",
            }
        },
    )


app = FastAPI(title=get_settings().app_name, lifespan=lifespan)
app.add_middleware(RequestContextLoggingmiddleware)


@app.get("/lb/health")
async def lb_health(request: Request):
    return {
        "load_balancer": "healthy",
        "backends": request.app.state.lb_state.backend_status,
        "configure_backends": request.app.state.settings.backends,
    }


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def catch_all(request: Request):
    return await proxy_request(request)
