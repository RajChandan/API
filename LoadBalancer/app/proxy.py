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


def filter_headers(header) -> Dict[str, str]:
    return {
        key: value
        for key, value in header.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


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

    start_time = time.perf_counter()
    try:
        body = await request.body()
        headers = filter_headers(request.headers)

        logger.info(
            "Proxying request",
            extra={
                "extra_data": {
                    "event": "proxy_request_started",
                    "service": matched_service.name,
                    "backend": backend,
                    "method": request.method,
                    "path": request.url.path,
                }
            },
        )

        upstream_response = await proxy_client.request(
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
