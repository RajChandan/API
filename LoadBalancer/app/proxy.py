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
