package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Gzip returns middleware that wraps the response writer in a gzip
// stream when the client advertised Accept-Encoding: gzip. Saves
// 70-90% bytes on JSON-heavy responses (audit lists, findings,
// dashboards) which is the typical shape for this API.
//
// Skipped automatically when:
//   - client didn't ask for gzip
//   - response is already encoded (e.g. SSE stream, file download,
//     pre-compressed evidence blobs)
//   - response is small (< minBytes) — gzip framing overhead exceeds
//     the savings on tiny payloads
//
// Uses a sync.Pool of gzip.Writers so steady-state throughput doesn't
// pay an allocation per request.
func Gzip(minBytes int) func(http.Handler) http.Handler {
	if minBytes <= 0 {
		minBytes = 1024 // 1 KiB; below this gzip framing hurts
	}
	pool := &sync.Pool{
		New: func() any {
			gz, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
			return gz
		},
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}
			gz := pool.Get().(*gzip.Writer)
			defer pool.Put(gz)

			grw := &gzipResponseWriter{
				ResponseWriter: w,
				gz:             gz,
				pool:           pool,
				minBytes:       minBytes,
			}
			defer grw.Close()
			next.ServeHTTP(grw, r)
		})
	}
}

// gzipResponseWriter buffers writes until it decides whether to
// compress. The decision is made on the first Write after a
// WriteHeader: if Content-Type indicates compressed-by-nature
// (event-stream, application/zip, image/*), pass through; if the
// accumulated body crosses minBytes, switch to gzip.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz       *gzip.Writer
	pool     *sync.Pool
	minBytes int

	hdrSent     bool
	mode        gzipMode // pending → passthrough or gzipping
	buf         []byte
	gzActive    bool
	statusCode  int
}

type gzipMode int

const (
	modePending gzipMode = iota
	modePassthrough
	modeGzip
)

func (g *gzipResponseWriter) WriteHeader(status int) {
	g.statusCode = status
	// Defer the actual WriteHeader until we know our mode — we need to
	// add/remove the Content-Encoding header before the headers are
	// flushed to the wire.
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if g.mode == modePassthrough {
		if !g.hdrSent {
			g.flushHeaders()
		}
		return g.ResponseWriter.Write(b)
	}
	if g.mode == modeGzip {
		return g.gz.Write(b)
	}
	// modePending: decide.
	if g.shouldPassthrough() {
		g.mode = modePassthrough
		g.flushHeaders()
		return g.ResponseWriter.Write(b)
	}
	g.buf = append(g.buf, b...)
	if len(g.buf) < g.minBytes {
		return len(b), nil
	}
	// Cross the threshold: switch to gzip.
	g.mode = modeGzip
	g.flushHeadersWithGzip()
	g.gz.Reset(g.ResponseWriter)
	g.gzActive = true
	if _, err := g.gz.Write(g.buf); err != nil {
		return 0, err
	}
	g.buf = nil
	return len(b), nil
}

// shouldPassthrough returns true if the response type is one that
// gzip wouldn't help (or would break, like SSE chunked streams).
func (g *gzipResponseWriter) shouldPassthrough() bool {
	ct := g.Header().Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		return true
	case strings.HasPrefix(ct, "image/"):
		return true
	case strings.HasPrefix(ct, "video/"):
		return true
	case ct == "application/zip", ct == "application/octet-stream",
		ct == "application/x-gzip", ct == "application/gzip":
		return true
	}
	// Already-encoded response (caller set Content-Encoding).
	if g.Header().Get("Content-Encoding") != "" {
		return true
	}
	return false
}

func (g *gzipResponseWriter) flushHeaders() {
	g.hdrSent = true
	if g.statusCode != 0 {
		g.ResponseWriter.WriteHeader(g.statusCode)
	}
}

func (g *gzipResponseWriter) flushHeadersWithGzip() {
	g.hdrSent = true
	h := g.ResponseWriter.Header()
	h.Set("Content-Encoding", "gzip")
	// Content-Length doesn't apply once we compress.
	h.Del("Content-Length")
	h.Add("Vary", "Accept-Encoding")
	if g.statusCode != 0 {
		g.ResponseWriter.WriteHeader(g.statusCode)
	}
}

// Close finalizes the response. Called via defer in the middleware.
// Handles three cases:
//   - mode never advanced past pending (small response that never
//     crossed minBytes): write the buffer uncompressed.
//   - passthrough: nothing to do; bytes already on the wire.
//   - gzip: close the gz writer to flush its trailer.
func (g *gzipResponseWriter) Close() {
	if g.mode == modePending {
		if !g.hdrSent {
			g.flushHeaders()
		}
		if len(g.buf) > 0 {
			_, _ = g.ResponseWriter.Write(g.buf)
		}
	}
	if g.gzActive {
		_ = g.gz.Close()
	}
}

// Flush exposes http.Flusher when the underlying ResponseWriter
// supports it. SSE handlers need this; our middleware doesn't
// intercept text/event-stream (it's a passthrough), so a chained
// gzip pass over SSE is a no-op and Flush proxies through.
func (g *gzipResponseWriter) Flush() {
	if g.mode == modeGzip {
		_ = g.gz.Flush()
	}
	if fl, ok := g.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
