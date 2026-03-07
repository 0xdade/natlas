from django.apps import AppConfig
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
    OTLPSpanExporter,
)
from opentelemetry.instrumentation.celery import CeleryInstrumentor
from opentelemetry.instrumentation.django import DjangoInstrumentor
from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


class InstrumentationConfig(AppConfig):
    name = "apps.instrumentation"

    def ready(self) -> None:
        from django.conf import settings  # noqa: PLC0415

        if not settings.OTEL_ENABLE:
            return

        print(f"OpenTelemetry enabled, reporting to {settings.OTEL_COLLECTOR} via gRPC")

        exporter = OTLPSpanExporter(endpoint=settings.OTEL_COLLECTOR, insecure=True)
        provider = TracerProvider(
            resource=Resource.create({"service.name": settings.OTEL_SERVICE_NAME})
        )
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        DjangoInstrumentor().instrument()
        PsycopgInstrumentor().instrument()
        CeleryInstrumentor().instrument()
        RedisInstrumentor().instrument()
