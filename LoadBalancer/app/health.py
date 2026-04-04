import asyncio
import logging
import httpx
from app.metrics import (
    BACKEND_HEALTH,
    BACKEND_CONSECUTIVE_FAILURES,
    BACKEND_CONSECUTIVE_SUCCESSES,
    BACKEND_PASSIVE_FAILURES,
)

logger = logging.getLogger("load_balancer.health")


def update_backend_metrics(backend: str, backend_state) -> None:
    BACKEND_HEALTH.labels(backend=backend).set(1 if backend_state.healthy else 0)
    BACKEND_CONSECUTIVE_FAILURES.labels(backend=backend).set(
        backend_state.consecutive_failures
    )
    BACKEND_CONSECUTIVE_SUCCESSES.labels(backend=backend).set(
        backend_state.consecutive_successes
    )
    BACKEND_PASSIVE_FAILURES.labels(backend=backend).set(backend_state.passive_failures)


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
                "failure_threshold": settings.health_failure_threshold,
                "success_threshold": settings.health_success_threshold,
            }
        },
    )

    while True:
        for backend in settings.backends:
            check_passed = await check_backend_health(
                client=client,
                backend=backend,
                timeout=settings.health_check_read_timeout,
            )

            async with lb_state.state_lock:
                backend_state = lb_state.backend_states[backend]
                previous_status = backend_state.healthy

                if check_passed:
                    backend_state.consecutive_failures = 0
                    backend_state.passive_failures = 0
                    backend_state.consecutive_successes += 1

                    if not backend_state.healthy:
                        if (
                            backend_state.consecutive_successes
                            >= settings.health_success_threshold
                        ):
                            backend_state.healthy = True
                            logger.info(
                                "Health check loop started",
                                extra={
                                    "extra_data": {
                                        "event": "health_check_loop_started",
                                        "interval_seconds": settings.health_check_interval,
                                        "failure_threshold": settings.health_failure_threshold,
                                        "success_threshold": settings.health_success_threshold,
                                    }
                                },
                            )
                else:
                    backend_state.consecutive_successes = 0
                    backend_state.consecutive_failures += 1

                    if backend_state.healthy:
                        if (
                            backend_state.consecutive_failures
                            >= settings.health_failure_threshold
                        ):
                            backend_state.healthy = False
                            logger.error(
                                "Backend marked unhealthy after active health check failures",
                                extra={
                                    "extra_data": {
                                        "event": "backend_marked_unhealthy_active",
                                        "backend": backend,
                                        "previous_status": previous_status,
                                        "current_status": backend_state.healthy,
                                        "consecutive_failures": backend_state.consecutive_failures,
                                    }
                                },
                            )
            update_backend_metrics(backend, backend_state)
            logger.debug(
                "Health check state updated",
                extra={
                    "extra_data": {
                        "event": "health_check_state_updated",
                        "backend": backend,
                        "healthy": backend_state.healthy,
                        "consecutive_failures": backend_state.consecutive_failures,
                        "consecutive_successes": backend_state.consecutive_successes,
                        "passive_failures": backend_state.passive_failures,
                    }
                },
            )

        await asyncio.sleep(settings.health_check_interval)
