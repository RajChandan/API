import asyncio
import logging
import time
import uuid

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response

from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.health import health_check_loop
from app.logging_config import configure_logging
from app.metrics import REQUEST_COUNT, REQUEST_DURATION, render_metrics
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
            duration_seconds = time.perf_counter() - start_time
            duration_ms = round(() * 1000, 2)
            response.headers["X-Request_ID"] = request_id

            REQUEST_COUNT.labels(
                method=request.method,
                path=request.url.path,
                status_code=str(response.status_code),
            ).inc()

            REQUEST_DURATION.labels(
                method=request.method, path=request.url.path
            ).observe(duration_seconds)

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
            duration_seconds = time.perf_counter() - start_time
            duration_ms = round(duration_seconds * 1000, 2)

            REQUEST_COUNT.labels(
                method=request.method, path=request.url.path, status_code="500"
            ).inc()
            REQUEST_DURATION.labels(
                method=request.method, path=request.url.path
            ).observe(duration_seconds)
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
    configure_logging(
        settings.log_level,
        settings.log_file,
        settings.log_max_bytes,
        settings.log_backup_count,
    )

    app.state.settings = settings
    app.state.lb_state = LoadBalancerState(backends=settings.backends)

    health_timeout = httpx.Timeout(
        connect=settings.health_check_connect_timeout,
        read=settings.health_check_read_timeout,
        write=settings.health_check_write_timeout,
        pool=settings.health_check_pool_timeout,
    )

    proxy_timeout = httpx.Timeout(
        connect=settings.proxy_connect_timeout,
        read=settings.proxy_read_timeout,
        write=settings.proxy_write_timeout,
        pool=settings.proxy_pool_timeout,
    )

    health_limits = httpx.Limits(
        max_connections=settings.health_max_connections,
        max_keepalive_connections=settings.health_max_keepalive_connections,
    )

    proxy_limits = httpx.Limits(
        max_connections=settings.proxy_max_connections,
        max_keepalive_connections=settings.proxy_max_keepalive_connections,
    )

    logger.info(
        "Application startup initiated",
        extra={
            "extra_data": {
                "event": "app_startup",
                "app_name": settings.app_name,
                "log_level": settings.log_level,
                "backends": settings.backends,
                "health_timeout": {
                    "connect": settings.health_check_connect_timeout,
                    "read": settings.health_check_read_timeout,
                    "write": settings.health_check_write_timeout,
                    "pool": settings.health_check_pool_timeout,
                },
                "proxy_timeout": {
                    "connect": settings.proxy_connect_timeout,
                    "read": settings.proxy_read_timeout,
                    "write": settings.proxy_write_timeout,
                    "pool": settings.proxy_pool_timeout,
                },
                "health_limits": {
                    "max_connections": settings.health_max_connections,
                    "max_keepalive_connections": settings.health_max_keepalive_connections,
                },
                "proxy_limits": {
                    "max_connections": settings.proxy_max_connections,
                    "max_keepalive_connections": settings.proxy_max_keepalive_connections,
                },
            }
        },
    )

    app.state.health_client = httpx.AsyncClient(
        timeout=health_timeout, limits=health_limits, follow_redirects=False
    )
    app.state.proxy_client = httpx.AsyncClient(
        timeout=proxy_timeout, limits=proxy_limits, follow_redirects=False
    )

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
    lb_state = request.app.state.lb_state

    return {
        "load_balancer": "healthy",
        "configured_backends": request.app.state.settings.backends,
        "backends": {
            backend: {
                "healthy": state.healthy,
                "consecutive_failures": state.consecutive_failures,
                "consecutive_successes": state.consecutive_successes,
                "passive_failures": state.passive_failures,
            }
            for backend, state in lb_state.backend_states.items()
        },
    }


@app.get("/lb/metrics")
async def lb_metrics():
    content, content_type = render_metrics()
    return Response(content=content, media_type=content_type)


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
async def catch_all(request: Request):
    return await proxy_request(request)
