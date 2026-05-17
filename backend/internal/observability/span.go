// span.go — thin tracing helpers for service-layer code.
//
// The goal is to give every service-method one line at the top:
//
//	ctx, end := observability.Span(ctx, "scanorch.Submit",
//	    "tenant_id", tenantID.String(),
//	    "engagement_id", engagementID.String())
//	defer end(err)
//
// …without each service package needing the full go.opentelemetry.io
// import set. The helper:
//
//	- starts a span keyed by the supplied name
//	- attaches the optional key/value attribute pairs
//	- returns a closer that, when called with the function's named
//	  return error, records it on the span (status + recordError)
//	  and ends the span
//
// When tracing is disabled (the no-op TracerProvider that InitTracing
// installs when VAULTSCAN_OTEL_EXPORTER is empty), every call is
// effectively zero-cost — otel skips the allocation entirely.
package observability

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// tracer is the global VAULTSCAN tracer. otel.Tracer caches by name
// so calling this on every Span() invocation is fine.
func tracer() trace.Tracer {
	return otel.Tracer("vaultscan")
}

// EndFunc closes a span. Pass the function's returned err (or nil)
// so the span gets the right status code + recordError.
type EndFunc func(err error)

// Span starts a child span and returns the context carrying it plus
// an end closure. kvs are alternating key/value strings; an odd
// count drops the trailing key (callers shouldn't write that, but
// dropping is safer than panicking).
//
// Standard span-name format: "package.Method" (e.g. "scanorch.Submit",
// "evidence.RecordWithDEK"). Sticking to this lets ops grep traces
// by Go-package + method.
func Span(ctx context.Context, name string, kvs ...string) (context.Context, EndFunc) {
	ctx, sp := tracer().Start(ctx, name)
	if len(kvs) > 0 {
		attrs := make([]attribute.KeyValue, 0, len(kvs)/2)
		for i := 0; i+1 < len(kvs); i += 2 {
			attrs = append(attrs, attribute.String(kvs[i], kvs[i+1]))
		}
		sp.SetAttributes(attrs...)
	}
	return ctx, func(err error) {
		if err != nil {
			sp.RecordError(err)
			sp.SetStatus(codes.Error, err.Error())
		}
		sp.End()
	}
}

// SpanInt is a convenience wrapper for spans with an integer attribute
// (counts, durations, sizes). Avoids the caller doing strconv.Itoa.
func SpanInt(ctx context.Context, name string, key string, val int) (context.Context, EndFunc) {
	ctx, sp := tracer().Start(ctx, name, trace.WithAttributes(attribute.Int(key, val)))
	return ctx, func(err error) {
		if err != nil {
			sp.RecordError(err)
			sp.SetStatus(codes.Error, err.Error())
		}
		sp.End()
	}
}

// AddAttr stamps additional attributes onto the active span without
// starting a new one. Used inside long-running spans to record state
// transitions ("decision=approved", "synthetic=true", etc).
func AddAttr(ctx context.Context, key, value string) {
	trace.SpanFromContext(ctx).SetAttributes(attribute.String(key, value))
}
