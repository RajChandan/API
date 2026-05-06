import logging
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumetion.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TraceProvider
from opentelemetry.sdk.trace.export import (BatchSpanProcessor,ConsoleSpanExporter)

logger = logging.getLogger(__name__)

def setup_telemetry(app:FastAPI,settings) -> None:
    if not settings.otel_enabled:
        logger.info("OpenTelemetry disabled",extra={"extra_data":{"event":"otel_disabled"
        }})

        return
    
    resource = Resource.create({"service.name":settings.otel_service_name,"service.version":"1.0.0","deployment.environment":"local"})

    provider = TraceProvider(resource=resource)
    trace.set_trace_provider(provider)

    if settings.otel_console_exporter_enabled:
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    if settings.otel_exporter_otlp_endpoint:
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{settings.otel_exporter_otlp_endpoint}/v1/traces")))

    
    FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor.instrument_client()

    logger.info(
        "OpenTelemetry initialized",
        extra={
            "extra_data": {
                "event": "otel_initialized",
                "service_name": settings.otel_service_name,
                "otlp_endpoint": settings.otel_exporter_otlp_endpoint,
                "console_exporter_enabled": settings.otel_console_exporter_enabled,
            }
        },
    )


def get_tracer():
    return trace.get_tracer("api_gateway")