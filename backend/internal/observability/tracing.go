package observability

import (
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// InitTracing wires the global TracerProvider. The exporter is chosen
// at runtime:
//   - VAULTSCAN_OTEL_EXPORTER=otlp + VAULTSCAN_OTEL_ENDPOINT set →
//     OTLP/HTTP exporter (production: ship to Tempo/Jaeger/Honeycomb)
//   - VAULTSCAN_OTEL_EXPORTER=stdout → stdout exporter (dev visibility)
//   - empty / "none" → no-op provider (the default, so tracing is
//     fully opt-in)
//
// Returns a shutdown function that flushes pending spans on process
// exit. Callers must defer it.
func InitTracing(ctx context.Context, serviceName, version string) (func(context.Context) error, error) {
	mode := os.Getenv("VAULTSCAN_OTEL_EXPORTER")
	if mode == "" || mode == "none" {
		return func(context.Context) error { return nil }, nil
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version),
		),
	)
	if err != nil {
		return nil, err
	}

	var exporter tracesdk.SpanExporter
	switch mode {
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
	case "otlp", "otlphttp":
		endpoint := os.Getenv("VAULTSCAN_OTEL_ENDPOINT")
		if endpoint == "" {
			return nil, errors.New("VAULTSCAN_OTEL_EXPORTER=otlp but VAULTSCAN_OTEL_ENDPOINT is empty")
		}
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
		if os.Getenv("VAULTSCAN_OTEL_INSECURE") == "true" {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		exporter, err = otlptracehttp.New(ctx, opts...)
	default:
		return nil, errors.New("VAULTSCAN_OTEL_EXPORTER must be 'otlp' | 'stdout' | 'none' (or empty)")
	}
	if err != nil {
		return nil, err
	}

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithBatcher(exporter, tracesdk.WithBatchTimeout(5*time.Second)),
		tracesdk.WithResource(res),
		tracesdk.WithSampler(tracesdk.ParentBased(tracesdk.TraceIDRatioBased(samplerRatio()))),
	)
	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// samplerRatio reads VAULTSCAN_OTEL_SAMPLE_RATIO (defaults to 0.1).
func samplerRatio() float64 {
	v := os.Getenv("VAULTSCAN_OTEL_SAMPLE_RATIO")
	if v == "" {
		return 0.1
	}
	var f float64
	_, err := scanFloat(v, &f)
	if err != nil || f < 0 || f > 1 {
		return 0.1
	}
	return f
}

func scanFloat(s string, dst *float64) (int, error) {
	var intPart, fracPart float64
	var sawDot bool
	var fracDiv float64 = 1
	for _, c := range s {
		switch {
		case c == '.' && !sawDot:
			sawDot = true
		case c >= '0' && c <= '9':
			d := float64(c - '0')
			if sawDot {
				fracDiv *= 10
				fracPart += d / fracDiv
			} else {
				intPart = intPart*10 + d
			}
		default:
			return 0, errors.New("not numeric")
		}
	}
	*dst = intPart + fracPart
	return 1, nil
}

// TracingHandler wraps an http.Handler so every request gets a span
// with the route name attached. Plays nicely with the metrics
// middleware — both are mounted in api.Mount.
func TracingHandler(next http.Handler, serviceName string) http.Handler {
	return otelhttp.NewHandler(next, serviceName,
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return r.Method + " " + routeLabel(r)
		}),
	)
}
