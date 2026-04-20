from prometheus_client import (
    Counter,
    Histogram,
    Gauge,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

GATEWAY_REQUEST_COUNT = Counter(
    "gateway_requests_total",
    "Total number of requests handled by the API gateway",
    ["service", "method", "path", "status_code"],
)

GATEWAY_REQUEST_DURATION = Histogram(
    "gateway_requests_duration_seconds",
    "Gateway request processing duration in seconds",
    ["service", "method", "path"],
)


GATEWAY_ROUTE_MISS_COUNT = Counter(
    "gateway_route_miss_total",
    "Total number of requests that did not match any route",
    ["method", "path"],
)


GATEWAY_NO_HEALTHY_BACKEND_COUNT = Counter(
    "gateway_no_healthy_backend_total",
    "Total number of times no healthy backend was available",
    ["service", "path"],
)


GATEWAY_PROXY_FAILURE_COUNT = Counter(
    "gateway_proxy_failure_total",
    "Total number of proxy failures in API gateway",
    ["service", "backend", "method", "path", "error_type"],
)

GATEWAY_BACKEND_HEALTH = Gauge(
    "gateway_backend_health",
    "Backend health status per service (1 = healthy, 0 = unhealthy)",
    ["service", "backend"],
)


GATEWAY_BACKEND_SELECTED = Counter(
    "gateway_backend_selected_total",
    "Total number of times a backend was selected for a service",
    ["service", "backend"],
)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
