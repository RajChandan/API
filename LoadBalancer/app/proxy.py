import asyncio
import logging
import time
from typing import Optional, Dict

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response


logger = logging.getLogger("load_balancer.proxy")

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
}


def filter_headers(header) -> Dict[str, str]:
    return {
        key: value
        for key, value in header.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def is_retryable_method(method: str, retry_methods: list[str]) -> bool:
    return method.upper() in retry_methods


def is_retryable_exception(exc: Exception) -> bool:
    retryable_exceptions = (
        httpx.connectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.ConnectError,
        httpx.RemoteProtocolError,
    )
    return isinstance(exc, retryable_exceptions)


def calculate_backoff_seconds(base_ms: int, attempt_number: int) -> float:
    return (base_ms * (2 ** (attempt_number - 1))) / 1000.0


async def get_next_backend(app) -> Optional[str]:
    lb_state = app.state.lb_state

    async with lb_state.selection_lock:
        healthy_backends = [
            backend
            for backend in lb_state.backends
            if lb_state.backend_states[backend].healthy
        ]

    if not healthy_backends:
        logger.error(
            "No healthy backends available",
            extra={
                "extra_data": {
                    "event": "no_healthy_backends",
                    "backend_status": lb_state.get_backend_status_view(),
                }
            },
        )
        return None

    for _ in range(len(lb_state.backends)):
        candidate = next(lb_state.backend_cycle)
        if candidate in healthy_backends:
            return candidate

    logger.error(
        "Failed to select a healthy backend",
        extra={
            "extra_data": {
                "event": "healthy_backend_selection_failed",
                "backend_status": lb_state.get_backend_status_view(),
            }
        },
    )
    return None


async def mark_backend_passive_failure(app, backend: str) -> None:
    settings = app.state.settings
    lb_state = app.state.lb_state

    async with lb_state.state_lock:
        backend_state = lb_state.backend_states[backend]
        backend_state.passive_failures += 1
        backend_state.consecutive_successes = 0

        if backend_state.passive_failures >= settings.passive_failure_threshold:
            if backend_state.healthy:
                backend_state.healthy = False
                logger.error(
                    "Backend marked unhealthy after passive proxy failures",
                    extra={
                        "extra_data": {
                            "event": "backend_marked_unhealthy_passive",
                            "backend": backend,
                            "passive_failures": backend_state.passive_failures,
                            "threshold": settings.passive_failure_threshold,
                        }
                    },
                )


async def reset_backend_passive_failure(app, backend: str) -> None:
    lb_state = app.state.lb_state
    async with lb_state.state_lock:
        backend_state = lb_state.backend_states[backend]
        backend_state.passive_failures = 0


async def proxy_request(request: Request):
    app = request.app
    settings = app.state.settings
    proxy_client = app.state.proxy_client
    request_id = getattr(request.state, "request_id", None)

    retry_allowed = settings.retry_enabled and is_retryable_method(
        request.method, settings.retry_on_methods
    )
    max_attempts = settings.retry_max_attempts if retry_allowed else 1

    body = await request.body()
    headers = filter_headers(request.headers)

    last_exception = None
    last_backend = None
    start_time = time.perf_counter()

    for attempt in range(1, max_attempts + 1):
        backend = await get_next_backend(app)
        last_backend = backend

        if not backend:
            return JSONResponse(
                status_code=503,
                content={"error": "No healthy backend available"},
            )

        target_url = httpx.URL(
            url=f"{backend}{request.url.path}",
            params=request.query_params,
        )

        logger.info(
            "Proxying request to backend",
            extra={
                "extra_data": {
                    "event": "proxy_request_started",
                    "request_id": request_id,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "method": request.method,
                    "path": request.url.path,
                    "query": str(request.query_params),
                    "backend": backend,
                    "client_ip": request.client.host if request.client else None,
                }
            },
        )

        try:
            upstream_response = await proxy_client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )

            await reset_backend_passive_failure(app, backend)

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response_headers = filter_headers(upstream_response.headers)

            logger.info(
                "Proxy request completed",
                extra={
                    "extra_data": {
                        "event": "proxy_request_completed",
                        "request_id": request_id,
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "method": request.method,
                        "path": request.url.path,
                        "backend": backend,
                        "status_code": upstream_response.status_code,
                        "duration_ms": duration_ms,
                    }
                },
            )

            return Response(
                content=upstream_response.content,
                status_code=upstream_response.status_code,
                headers=response_headers,
                media_type=upstream_response.headers.get("content-type"),
            )

        except httpx.RequestError as exc:
            last_exception = exc
            await mark_backend_passive_failure(app, backend)

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            retryable_error = is_retryable_exception(exc)
            should_retry = retry_allowed and retryable_error and attempt < max_attempts

            logger.exception(
                "Proxy request failed",
                extra={
                    "extra_data": {
                        "event": "proxy_request_failed",
                        "request_id": request_id,
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "method": request.method,
                        "path": request.url.path,
                        "backend": backend,
                        "duration_ms": duration_ms,
                        "error_type": exc.__class__.__name__,
                        "retryable_error": retryable_error,
                        "retry_allowed": retry_allowed,
                        "should_retry": should_retry,
                    }
                },
            )

            if should_retry:
                backoff_seconds = calculate_backoff_seconds(
                    settings.retry_backoff_base_ms,
                    attempt,
                )

                logger.warning(
                    "Retrying proxy request after transient failure",
                    extra={
                        "extra_data": {
                            "event": "proxy_request_retry_scheduled",
                            "request_id": request_id,
                            "attempt": attempt,
                            "next_attempt": attempt + 1,
                            "backend": backend,
                            "backoff_seconds": backoff_seconds,
                            "error_type": exc.__class__.__name__,
                        }
                    },
                )

                await asyncio.sleep(backoff_seconds)
                continue

            break

    total_duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return JSONResponse(
        status_code=502,
        content={
            "error": "Failed to forward request",
            "details": (
                str(last_exception) if last_exception else "Unknown upstream failure"
            ),
            "backend": last_backend,
            "duration_ms": total_duration_ms,
        },
    )
