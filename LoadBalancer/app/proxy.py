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


async def get_next_backend(app) -> Optional[str]:
    lb_state = app.state.lb_state

    async with lb_state.selection_lock:
        healthy_backends = [
            backend
            for backend in lb_state.backends
            if lb_state.backend_status.get(backend, False)
        ]

    if not healthy_backends:
        logger.error(
            "No healthy backends available",
            extra={
                "extra_data": {
                    "event": "no_healthy_backends",
                    "backend_status": lb_state.backend_status.copy(),
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
                "backend_status": lb_state.backend_status.copy(),
            }
        },
    )
    return None


async def proxy_request(request: Request):
    app = request.app
    settings = app.state.settings
    proxy_client = app.state.proxy_client
    request_id = getattr(request.state, "request_id", None)

    backend = await get_next_backend(app)
    if not backend:
        return JSONResponse(
            status_code=503, content={"error": "No healthy backend available"}
        )

    target_url = httpx.URL(
        url=f"{backend}{request.url.path}", params=request.query_params
    )

    logger.info(
        "Proxying request to backend",
        extra={
            "extra_data": {
                "event": "proxy_request_started",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params),
                "backend": backend,
                "client_ip": request.client.host if request.client else None,
            }
        },
    )

    start_time = time.perf_counter()

    try:
        body = await request.body()
        headers = filter_headers(request.headers)

        upstream_response = await proxy_client.request(
            method=request.method, url=target_url, headers=headers, content=body
        )

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        response_headers = filter_headers(upstream_response.headers)

        logger.info(
            "Proxying request to backend",
            extra={
                "extra_data": {
                    "event": "proxy_request_started",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "query": str(request.query_params),
                    "backend": backend,
                    "client_ip": request.client.host if request.client else None,
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
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.exception(
            "Proxy request failed",
            extra={
                "extra_data": {
                    "event": "proxy_request_failed",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "backend": backend,
                    "duration_ms": duration_ms,
                    "error_type": exc.__class__.__name__,
                }
            },
        )

        return JSONResponse(
            status_code=502,
            content={
                "error": "Failed to forward request",
                "details": str(exc),
                "backend": backend,
            },
        )
