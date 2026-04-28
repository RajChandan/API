import asyncio
import logging
import time
from typing import Optional, Dict, List

import httpx
from fastapi import Request, Header, HTTPException
from fastapi.responses import JSONResponse, Response

from app.metrics import (
    GATEWAY_BACKEND_SELECTED,
    GATEWAY_NO_HEALTHY_BACKEND_COUNT,
    GATEWAY_PROXY_FAILURE_COUNT,
    GATEWAY_ROUTE_MISS_COUNT,
)

from app.router import match_service
from app.auth import AuthError, authenticate_request, build_identity_headers

logger = logging.getLogger("api_gateway.proxy")

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


SENSETIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "proxy-authorization",
}


def filter_headers(header) -> Dict[str, str]:
    return {
        key: value
        for key, value in header.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def sanitize_headers_for_logging(headers) -> dict[str, str]:
    sanitized = {}

    for key, value in headers.items():
        if key.lower() in SENSETIVE_HEADERS:
            sanitized[key] = "***REDACTED***"
        else:
            sanitized[key] = value
    return sanitized


async def get_next_backend(service_state) -> Optional[str]:
    available_backends = []

    for backend in service_state.backends:
        state = service_state.backend_states[backend]

        if not state.healthy:
            continue

        if state.is_ejected():
            continue

        available_backends.append(backend)

    if not available_backends:
        return None

    for _ in range(len(service_state.backends)):
        candidate = next(service_state.backend_cycle)
        candidate_state = service_state.backend_states[candidate]

        if candidate in available_backends and not candidate_state.is_ejected():
            return candidate

    return None


def record_backend_success(service_state, backend: str) -> None:
    backend_state = service_state.backend_states[backend]
    backend_state.consecutive_failures = 0
    backend_state.ejected_until = None


def record_backend_failure(service_state, backend: str) -> None:
    policy = service_state.policy
    backend_state = service_state.backend_states[backend]
    backend_state.consecutive_failure += 1

    if not policy.circuit_breaker_enabled:
        return

    if backend_state.consecutive_failures >= policy.circuit_breaker_failure_threshold:
        backend_state.ejected_until = (
            time.time() + policy.circuit_breaker_ejection_seconds
        )
        logger.error(
            "Backend ejected by circuit breaker",
            extra={
                "extra_data": {
                    "event": "backend_ejected",
                    "service": service_state.name,
                    "backend": backend,
                    "consecutive_failures": backend_state.consecutive_failures,
                    "ejection_seconds": policy.circuit_breaker_ejection_seconds,
                    "ejected_until": backend_state.ejected_until,
                }
            },
        )


def is_authorized(request: Request, expected_api_key: str | None) -> bool:
    if not expected_api_key:
        return True
    provided_key = request.headers.get("x-api-key")
    return provided_key == expected_api_key


def is_retryable_method(method: str, retry_methods: List[str]) -> bool:
    return method.upper() in retry_methods


def is_retryable_exception(exc: Exception) -> bool:
    retryable_exceptions = (
        httpx.ConnectTimeout,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.PoolTimeout,
        httpx.ConnectError,
        httpx.RemoteProtocolError,
    )
    return isinstance(exc, retryable_exceptions)


def calculate_retry_backoff_seconds(base_ms: int, attempt: int) -> float:
    return (base_ms * (2 ** (attempt - 1))) / 1000.0


async def proxy_request(request: Request):
    app = request.app
    gateway_state = app.state.gateway_state

    matched_service = match_service(request.url.path, gateway_state)

    if not matched_service:
        GATEWAY_ROUTE_MISS_COUNT.labels(
            method=request.method, path=request.url.path
        ).inc()
        logger.warning(
            "No route matched",
            extra={
                "extra_data": {
                    "event": "route_not_found",
                    "path": request.url.path,
                    "method": request.method,
                }
            },
        )
        return JSONResponse(
            status_code=404, content={"error": "No matching service route found"}
        )

    policy = matched_service.policy

    if request.method.upper() not in policy.allowed_methods:
        logger.warning(
            "Method not allowed for service",
            extra={
                "extra_data": {
                    "event": "service_method_not_allowed",
                    "service": matched_service.name,
                    "method": request.method,
                    "path": request.url.path,
                    "allowed_methods": policy.allowed_methods,
                }
            },
        )
        return JSONResponse(
            status_code=405,
            content={
                "error": "Method not allowed",
                "service": matched_service.name,
                "allowed_methods": policy.allowed_methods,
            },
        )

    identity_headers = {}
    if policy.require_auth:
        try:
            jwt_payload = authenticate_request(request)
            identity_headers = build_identity_headers(jwt_payload)

        except AuthError as exc:
            logger.warning(
                "JWT authentication failed",
                extra={
                    "extra_data": {
                        "event": "jwt_auth_failed",
                        "service": matched_service.name,
                        "method": request.method,
                        "path": request.url.path,
                        "reason": str(exc),
                    }
                },
            )
            return JSONResponse(
                status_code=401,
                content={
                    "error": "Unauthorized",
                    "service": matched_service.name,
                    "reason": str(exc),
                },
            )

    body = await request.body()
    if len(body) > policy.max_request_body_bytes:
        logger.warning(
            "Request body too large for service",
            extra={
                "extra_data": {
                    "event": "service_body_too_large",
                    "service": matched_service.name,
                    "method": request.method,
                    "path": request.url.path,
                    "body_size_bytes": len(body),
                    "max_allowed_bytes": policy.max_request_body_bytes,
                }
            },
        )

        return JSONResponse(
            status_code=413,
            content={
                "error": "Request body too large",
                "service": matched_service.name,
            },
        )

    retry_allowed = policy.retry_enabled and is_retryable_method(
        request.method, policy.retry_on_methods
    )

    max_attempts = policy.retry_max_attempts if retry_allowed else 1

    last_exception = None
    last_backend = None

    for attempt in range(1, max_attempts + 1):
        backend = await get_next_backend(matched_service)
        last_backend = backend

        if not backend:
            GATEWAY_NO_HEALTHY_BACKEND_COUNT.labels(
                service=matched_service.name, path=request.url.path
            ).inc()
            return JSONResponse(
                status_code=503,
                content={
                    "error": "No healthy backend available",
                    "service": matched_service.name,
                },
            )

        GATEWAY_BACKEND_SELECTED.labels(
            service=matched_service.name, backend=backend
        ).inc()
        target_url = httpx.URL(
            url=f"{backend}{request.url.path}", params=request.query_params
        )

        headers = filter_headers(request.headers)
        headers.update(identity_headers)
        start_time = time.perf_counter()

        try:

            logger.info(
                "Proxying request with service policy",
                extra={
                    "extra_data": {
                        "event": "proxy_request_started",
                        "service": matched_service.name,
                        "backend": backend,
                        "method": request.method,
                        "path": request.url.path,
                        "service_policy": {
                            "allowed_methods": policy.allowed_methods,
                            "require_auth": policy.require_auth,
                            "max_request_body_bytes": policy.max_request_body_bytes,
                            "connect_timeout": policy.connect_timeout,
                            "read_timeout": policy.read_timeout,
                            "write_timeout": policy.write_timeout,
                            "pool_timeout": policy.pool_timeout,
                        },
                        "request_headers": sanitize_headers_for_logging(headers),
                    }
                },
            )

            if matched_service.client is None:
                return JSONResponse(
                    status_code=503,
                    content={
                        "error": "Service HTTP client is not initialized",
                        "service": matched_service.name,
                    },
                )

            upstream_response = await matched_service.client.request(
                method=request.method, url=target_url, headers=headers, content=body
            )
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            response_headers = filter_headers(upstream_response.headers)
            record_backend_success(matched_service, backend)

            logger.info(
                "Proxy request completed",
                extra={
                    "extra_data": {
                        "event": "proxy_request_completed",
                        "service": matched_service.name,
                        "backend": backend,
                        "method": request.method,
                        "path": request.url.path,
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
            GATEWAY_PROXY_FAILURE_COUNT.labels(
                service=matched_service.name,
                backend=backend,
                method=request.method,
                path=request.url.path,
                error_type=exc.__class__.__name__,
            ).inc()
            record_backend_failure(matched_service, backend)
            retryable_error = is_retryable_exception(exc)
            should_retry = retry_allowed and retryable_error and attempt < max_attempts
            logger.exception(
                "Proxy request failed",
                extra={
                    "extra_data": {
                        "event": "proxy_request_failed",
                        "service": matched_service.name,
                        "backend": backend,
                        "method": request.method,
                        "path": request.url.path,
                        "error_type": exc.__class__.__name__,
                        "attempt": attempt,
                        "max_attempts": max_attempts,
                        "retryable_error": retryable_error,
                        "should_retry": should_retry,
                    }
                },
            )

            if should_retry:
                backoff_seconds = calculate_retry_backoff_seconds(
                    policy.retry_backoff_ms, attempt
                )
                logger.warning(
                    "Retrying request",
                    extra={
                        "extra_data": {
                            "event": "proxy_retry_scheduled",
                            "service": matched_service.name,
                            "backend": backend,
                            "attempt": attempt,
                            "next_attempt": attempt + 1,
                            "backoff_seconds": backoff_seconds,
                        }
                    },
                )
                await asyncio.sleep(backoff_seconds)
                continue
    return JSONResponse(
        status_code=502,
        content={
            "error": "Failed to forward request",
            "service": matched_service.name,
            "backend": backend,
            "details": str(exc),
        },
    )
