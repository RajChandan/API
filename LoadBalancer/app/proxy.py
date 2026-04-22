import asyncio
import logging
import time
from typing import Optional, Dict

import httpx
from fastapi import Request
from fastapi.responses import JSONResponse, Response

from app.metrics import (
    GATEWAY_BACKEND_SELECTED,
    GATEWAY_NO_HEALTHY_BACKEND_COUNT,
    GATEWAY_PROXY_FAILURE_COUNT,
    GATEWAY_ROUTE_MISS_COUNT,
)

from app.router import match_service

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
    healthy_backends = [
        backend
        for backend in service_state.backends
        if service_state.backend_states[backend].healthy
    ]

    if not healthy_backends:
        return None

    for _ in range(len(service_state.backends)):
        candidate = next(service_state.backend_cycle)
        if candidate in healthy_backends:
            return candidate
    return None


def is_authorized(request: Request, expected_api_key: str | None) -> bool:
    if not expected_api_key:
        return True
    provided_key = request.headers.get("x-api-key")
    return provided_key == expected_api_key


async def proxy_request(request: Request):
    app = request.app
    proxy_client = app.state.proxy_client
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

    if policy.require_auth and not is_authorized(
        request, app.state.settings.gateway_api_key
    ):
        logger.warning(
            "Unauthorized request for protected service",
            extra={
                "extra_data": {
                    "event": "service_auth_failed",
                    "service": matched_service.name,
                    "method": request.method,
                    "path": request.url.path,
                }
            },
        )
        return JSONResponse(
            status_code=401,
            content={"error": "Unauthorized", "service": matched_service.name},
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

    backend = get_next_backend(matched_service)

    if not backend:

        GATEWAY_NO_HEALTHY_BACKEND_COUNT.labels(
            service=matched_service.name, path=request.url.path
        ).inc()
        logger.error(
            "No healthy backend available for service",
            extra={
                "extra_data": {
                    "event": "no_healthy_backend_for_service",
                    "service": matched_service.name,
                    "path": request.url.path,
                }
            },
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "No healthy backend available",
                "service": matched_service.name,
            },
        )

    GATEWAY_BACKEND_SELECTED.labels(service=matched_service.name, backend=backend).inc()
    target_url = httpx.URL(
        url=f"{backend}{request.url.path}", params=request.query_params
    )

    headers = filter_headers(request.headers)
    start_time = time.perf_counter()
    timeout = httpx.Timeout(
        connect=policy.connect_timeout,
        read=policy.read_timeout,
        write=policy.write_timeout,
        pool=policy.pool_timeout,
    )
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

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            upstream_response = await client.request(
                method=request.method, url=target_url, headers=headers, content=body
            )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response_headers = filter_headers(upstream_response.headers)

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
        GATEWAY_PROXY_FAILURE_COUNT.labels(
            service=matched_service.name,
            backend=backend,
            method=request.method,
            path=request.url.path,
            error_type=exc.__class__.__name__,
        ).inc()
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
                }
            },
        )

        return JSONResponse(
            status_code=502,
            content={
                "error": "Failed to forward request",
                "service": matched_service.name,
                "backend": backend,
                "details": str(exc),
            },
        )
