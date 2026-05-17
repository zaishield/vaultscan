// etag.go — weak ETag generation + If-None-Match short-circuit
// on safe GET responses.
//
// Pattern: middleware buffers the response body, computes a
// content hash, sets `ETag: W/"<sha256-prefix>"`. If the request
// carried `If-None-Match: W/"<...>"` and the hash matches, we
// short-circuit with 304 Not Modified — saves bandwidth + lets
// clients trust their local cache for unchanged data.
//
// Scope: GET only. Other methods bypass; their responses aren't
// cacheable in the same way and ETag carries no useful signal.
// SSE and stream-style responses are also bypassed by checking
// Content-Type after the handler returns.

package middleware

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// ETag returns middleware that adds weak ETags to GET responses and
// honours If-None-Match. Skip-list:
//   - non-GET methods
//   - responses already carrying an ETag (handler set its own)
//   - SSE / stream / chunked responses (Content-Type prefix match)
//   - 5xx / 3xx responses (caching errors / redirects is wrong)
//   - empty bodies
func ETag() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				next.ServeHTTP(w, r)
				return
			}
			buf := &etagWriter{
				ResponseWriter: w,
				buf:            bytes.NewBuffer(nil),
			}
			next.ServeHTTP(buf, r)
			if buf.streamed {
				// Flushed mid-handler (SSE / streaming): headers + early
				// bytes already on the wire. Nothing to do here.
				return
			}
			body := buf.buf.Bytes()
			status := buf.statusCode
			if status == 0 {
				status = http.StatusOK
			}
			// Non-cacheable responses: write status + body as-is.
			ct := w.Header().Get("Content-Type")
			if status >= 300 || len(body) == 0 ||
				strings.HasPrefix(ct, "text/event-stream") ||
				strings.HasPrefix(ct, "multipart/") {
				w.WriteHeader(status)
				_, _ = w.Write(body)
				return
			}
			// Compute ETag if the handler didn't set one.
			tag := w.Header().Get("ETag")
			if tag == "" {
				sum := sha256.Sum256(body)
				tag = `W/"` + hex.EncodeToString(sum[:16]) + `"` // 128 bits, weak
				w.Header().Set("ETag", tag)
			}
			// If-None-Match hit → 304 Not Modified. RFC 7232 forbids
			// a body or Content-Length on 304.
			if match := r.Header.Get("If-None-Match"); match != "" && matchesETag(match, tag) {
				w.Header().Del("Content-Length")
				w.Header().Del("Content-Type")
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write(body)
		})
	}
}

// matchesETag is a permissive single-value comparator. RFC 7232
// allows a list (comma-separated) and a "*" wildcard. We honour
// both: wildcard matches anything, list matches any element.
func matchesETag(headerVal, tag string) bool {
	headerVal = strings.TrimSpace(headerVal)
	if headerVal == "*" {
		return true
	}
	for _, item := range strings.Split(headerVal, ",") {
		if strings.TrimSpace(item) == tag {
			return true
		}
	}
	return false
}

// etagWriter buffers Write/WriteHeader so the middleware can hash
// the body before flushing. If the handler explicitly calls Flush
// (SSE, streaming), we mark streamed=true and bypass etag entirely.
type etagWriter struct {
	http.ResponseWriter
	buf        *bytes.Buffer
	statusCode int
	hdrSent    bool
	streamed   bool
}

func (e *etagWriter) WriteHeader(status int) {
	e.statusCode = status
	// Defer the WriteHeader to the middleware so we can decide on
	// 304 vs 200 after hashing. Handler-supplied headers are still
	// on the wire via Header().
}

func (e *etagWriter) Write(b []byte) (int, error) {
	if e.streamed {
		return e.ResponseWriter.Write(b)
	}
	e.buf.Write(b)
	return len(b), nil
}

// Flush is the signal that the handler is streaming. We can no
// longer buffer + ETag; commit what we have and pass through.
func (e *etagWriter) Flush() {
	if !e.streamed {
		if e.statusCode == 0 {
			e.statusCode = http.StatusOK
		}
		e.ResponseWriter.WriteHeader(e.statusCode)
		if e.buf.Len() > 0 {
			_, _ = e.ResponseWriter.Write(e.buf.Bytes())
			e.buf.Reset()
		}
		e.streamed = true
	}
	if fl, ok := e.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
