import asyncio
import logging
import httpx

from app.metrics import GATEWAY_BACKEND_HEALTH

logger = logging.getLogger("API_Gateway.health")


async def check_backend_health(client: httpx.AsyncClient, backend: str) -> bool:
    try:
        response = await client.get(f"{backend}/health")
        return response.status_code == 200
    except Exception:
        return False





async def health_check_loop(app):
    gateway_state = app.state.gateway_state
    client = app.state.health_client

    logger.info(
        "Gateway health check loop started",
        extra={
            "extra_data": {
                "event": "gateway_health_loop_started",
                "service_count": len(gateway_state.services),
            }
        },
    )

    while True:
        for service_name, service_state in gateway_state.services.items():
            for backend in service_state.backends:
                is_healthy = await check_backend_health(client, backend)
                previous = service_state.backend_states[backend].healthy
                service_state.backend_states[backend].healthy = is_healthy

                GATEWAY_BACKEND_HEALTH.labels(service=service_name,backend=backend).set(1 if is_healthy else 0)

                if previous != is_healthy:
                    logger.warning(
                        "Backend health changed",
                        extra={
                            "extra_data": {
                                "event": "backend_health_changed",
                                "service": service_name,
                                "backend": backend,
                                "previous_status": previous,
                                "current_status": is_healthy,
                            }
                        },
                    )
            await asyncio.sleep(5)
