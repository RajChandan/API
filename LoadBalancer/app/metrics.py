from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

REQUEST_COUNT = Counter(
    "lb_requests_total",
    "Total number of incoming requests handled by the load balancer",
    ["method", "path", "status_code"],
)

REQUEST_DURATION = Histogram(
    "lb_request_duration_seconds",
    "Request processing duration in seconds",
    ["method", "path"],
)

PROXY_RETRY_COUNT = Counter(
    "lb_proxy_retries_total",
    "Total number of proxy retries asttmpted",
    ["method", "path", "backend"],
)

PROXY_FAILURE_COUNT = Counter(
    "lb_proxy_failure_total",
    "Total number of proxy failures",
    ["method", "path", "backend", "error_type"],
)

NO_HEALTHY_BACKEND_COUNT = Counter(
    "lb_no_healthy_backends_total",
    "Total number of times no healthy backends were available",
)

BACKEND_HEALTH = Gauge(
    "lb_backend_healthy",
    "Backend health status (1 = healthy, 0 = unhealthy)",
    ["backend"],
)

BACKEND_CONSECUTIVE_FAILURES = Gauge(
    "lb_backend_consecutive_failures",
    "Number of consecutive failures for each backend",
    ["backend"],
)

BACKEND_CONSECUTIVE_SUCCESSES = Gauge(
    "lb_backend_consecutive_successes",
    "Current consecutive active heralth check successes per backend",
    ["backend"],
)

BACKEND_PASSIVE_FAILURES = Gauge(
    "lb_backend_passive_failures",
    "Current passive failures per backend",
    ["backend"],
)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
