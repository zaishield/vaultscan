package observability

import (
	"context"
	"errors"
	"testing"
)

func TestSpan_NilCtxDoesNotPanic(t *testing.T) {
	// The OTel global tracer panics on context.WithValue(nil, ...).
	// Our Span wrapper must coerce nil to Background.
	ctx, end := Span(nil, "test.span")
	if ctx == nil {
		t.Fatal("Span returned nil ctx")
	}
	end(nil)
}

func TestSpan_EndWithErrorIsSafe(t *testing.T) {
	ctx, end := Span(context.Background(), "test.with_err",
		"key1", "v1", "key2", "v2")
	if ctx == nil {
		t.Fatal("ctx nil")
	}
	end(errors.New("boom"))
}

func TestSpan_OddKvsDropsTrailingKey(t *testing.T) {
	// 3 kvs = key + value + trailing key with no value. Should NOT
	// panic; we silently drop the trailing key.
	ctx, end := Span(context.Background(), "test.odd_kvs",
		"k1", "v1", "trailing_key")
	if ctx == nil {
		t.Fatal("ctx nil")
	}
	end(nil)
}

func TestSpanInt_NilCtxDoesNotPanic(t *testing.T) {
	ctx, end := SpanInt(nil, "test.int_span", "count", 42)
	if ctx == nil {
		t.Fatal("nil ctx returned")
	}
	end(nil)
}

func TestSpanInt_EndWithError(t *testing.T) {
	ctx, end := SpanInt(context.Background(), "test.int_err", "size", 100)
	end(errors.New("size-related failure"))
	_ = ctx
}

func TestAddAttr_DoesNotPanic(t *testing.T) {
	// AddAttr on a context without an active span should no-op,
	// not panic.
	AddAttr(context.Background(), "k", "v")
	AddAttr(context.TODO(), "x", "y")
}
