import asyncio
import logging
import httpx


logger = logging.getLogger("load_balancer.health")


async def check_backend_health(
    client: httpx.AsyncClient, backend: str, timeout: float
) -> bool:
    try:
        response = await client.get(f"{backend}/health", timeout=timeout)
        return response.status_code == 200
    except Exception:
        return False


async def health_check_loop(app):
    settings = app.state.settings
    lb_state = app.state.lb_state
    client = app.state.health_client

    logger.info(
        "Health check loop started",
        extra={
            "extra_data": {
                "event": "health_check_loop_started",
                "interval_seconds": settings.health_check_interval,
                "timeout_seconds": settings.health_check_timeout,
            }
        },
    )

    while True:
        for backend in settings.backends:
            previous_state = lb_state.backend_status.get(backend, True)
            is_healthy = await check_backend_health(
                client=client,
                backend=backend,
                timeout=settings.health_check_timeout,
            )

            lb_state.backend_status[backend] = is_healthy

            if previous_state != is_healthy:
                logger.info(
                    "Health check loop started",
                    extra={
                        "extra_data": {
                            "event": "health_check_loop_started",
                            "interval_seconds": settings.health_check_interval,
                            "timeout_seconds": settings.health_check_timeout,
                        }
                    },
                )

            logger.debug(
                "Health check cycle completed",
                extra={
                    "extra_data": {
                        "event": "health_check_cycle_completed",
                        "backend_status": lb_state.backend_status.copy(),
                    }
                },
            )

        await asyncio.sleep(settings.health_check_interval)
