import asyncio
from contextlib import asynccontextmanager
from itertools import cycle
from typing import Dict, List, Optional
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

BACKENDS = ["http://127.0.0.1:9001", "http://127.0.0.1:9002", "http://127.0.0.1:9003"]

HEALTH_CHECK_INTERVAL = 5
HEALTH_CHECK_TIMEOUT = 2.0
PROXY_TIMEOUT = 10.0

backend_status: Dict[str, bool] = {backend: True for backend in BACKENDS}
backend_cycle = cycle(BACKENDS)
selection_lock = asyncio.Lock()


async def check_backend_health(client: httpx.AsyncClient, backend: str) -> bool:
    try:
        response = await client.get(f"{backend}/health", timeout=HEALTH_CHECK_TIMEOUT)
        return response.status_code == 200
    except Exception:
        return False


async def health_check_loop():
    while True:
        async with httpx.AsyncClient() as client:
            for backend in BACKENDS:
                is_healthy = await check_backend_health(client, backend)
                backend_status[backend] = is_healthy

        print(f"Health check results: {backend_status}")
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)


async def get_next_backend() -> Optional[str]:
    async with selection_lock:
        healthy_backends = [b for b in BACKENDS if backend_status.get(b, False)]

        if not healthy_backends:
            return None

        for _ in range(len(BACKENDS)):
            candidate = next(backend_cycle)
            if candidate in healthy_backends:
                return candidate
        return None


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
