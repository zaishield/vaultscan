// idempotency.go — RFC-style Idempotency-Key middleware.
//
// The contract:
//
//   * Clients SHOULD send `Idempotency-Key: <uuid>` on every POST /
//     PUT / PATCH. The header is the client's promise: "I will retry
//     this request with the same body and the same key if I don't
//     get a confirmed response."
//
//   * Server (this middleware) hashes (method + path + body) and
//     pairs it with the key. On a duplicate:
//
//       - Same body → replay the cached response. 200 OK becomes
//         200 OK, 422 becomes 422, etc. Side effects are NOT run
//         twice.
//
//       - Different body → 409 Conflict. The client violated the
//         "retry with the same body" contract; we refuse rather
//         than execute a new side effect under a key that's already
//         been committed to a different outcome.
//
//       - In-flight: another request with this key is currently
//         executing. Respond with 409 + Retry-After so the client
//         backs off without us double-firing the handler.
//
//   * Keys expire after 24h (set by the DB default). Sweeper cron
//     deletes expired rows.
//
// Without this middleware, every network glitch on the client side
// risked a duplicate scan submission / duplicate emergency-stop /
// duplicate finding state transition. That's a real production bug,
// not a theoretical one.

package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

// IdempotencyHitSink mirrors the rate-limit sink — the API package
// wires in an observability counter at startup so we can chart
// new vs replayed vs conflicted hits without an import cycle.
var idempotencyHits = func(outcome string) {}

// SetIdempotencyHitSink lets the API wire metrics for the
// vaultscan_idempotency_hits_total{outcome=...} counter.
func SetIdempotencyHitSink(f func(outcome string)) {
	if f != nil {
		idempotencyHits = f
	}
}

// Idempotency returns middleware that intercepts POST/PUT/PATCH
// requests carrying an Idempotency-Key header. GET/HEAD/DELETE pass
// through (safe + idempotent by definition).
//
// Pool is the application's pgxpool; the middleware uses it to
// persist the key store.
func Idempotency(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !shouldIntercept(r.Method) {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get("Idempotency-Key")
			if key == "" {
				// Clients are not REQUIRED to send the header; if
				// they don't, no replay protection — same as before.
				next.ServeHTTP(w, r)
				return
			}
			if !looksLikeKey(key) {
				writeJSONError(w, http.StatusBadRequest,
					"bad_idempotency_key",
					"Idempotency-Key must be a UUID or 8-128 char token")
				return
			}

			// Read the body so we can hash it AND replay it to the
			// downstream handler. We bound by the global MaxBodySize
			// middleware so this isn't unbounded.
			body, err := io.ReadAll(r.Body)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest,
					"bad_request", "body read failed")
				return
			}
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(body))

			hash := requestHash(r.Method, r.URL.Path, body)
			tenantID := tenantIDOrNil(r)

			// Insert in-flight row OR look up existing.
			existing, inserted, err := claim(r.Context(), pool, tenantID, key, hash)
			if err != nil {
				// DB failure on the claim path defeats the
				// at-most-once guarantee. Previous behaviour was to
				// fall through to running the handler — that's
				// fail-OPEN and silently turns idempotent calls into
				// "execute multiple times if the DB hiccups", which
				// is the exact opposite of what Idempotency-Key
				// promises. Fail closed with 503 + a hint so the
				// client retries when the claim store recovers.
				idempotencyHits("claim_error")
				w.Header().Set("Retry-After", "2")
				writeJSONError(w, http.StatusServiceUnavailable,
					"idempotency_store_unavailable",
					"idempotency-key claim store is unavailable; retry shortly")
				return
			}
			if !inserted {
				// Existing row. Replay or conflict.
				if existing.status == "in_flight" {
					idempotencyHits("inflight")
					w.Header().Set("Retry-After", "2")
					writeJSONError(w, http.StatusConflict,
						"idempotency_in_flight",
						"another request with this key is currently being processed")
					return
				}
				if !bytes.Equal(existing.requestHash, hash) {
					idempotencyHits("conflict")
					writeJSONError(w, http.StatusConflict,
						"idempotency_conflict",
						"Idempotency-Key reused with a different request body")
					return
				}
				// Same key, same body, completed → replay.
				idempotencyHits("replayed")
				replay(w, existing)
				return
			}

			// New key: run the handler with a capturing writer, then
			// persist the response so a future retry replays it.
			idempotencyHits("new")
			cap := &captureWriter{
				ResponseWriter: w,
				body:           bytes.NewBuffer(nil),
				header:         http.Header{},
			}
			next.ServeHTTP(cap, r)
			finalize(r.Context(), pool, tenantID, key, cap)
		})
	}
}

func shouldIntercept(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

// looksLikeKey accepts a UUID OR a sanity-bounded opaque token.
// Rejects empty / whitespace and unreasonably long keys (DoS via
// huge keys filling the table).
func looksLikeKey(s string) bool {
	if len(s) < 8 || len(s) > 128 {
		return false
	}
	if _, err := uuid.Parse(s); err == nil {
		return true
	}
	// Allow opaque tokens (e.g. ULID, ksuid) that aren't UUIDs.
	// Restrict to ASCII printable to keep request_hash predictable.
	for _, c := range s {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

func requestHash(method, path string, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{' '})
	h.Write([]byte(path))
	h.Write([]byte{' '})
	h.Write(body)
	return h.Sum(nil)
}

func tenantIDOrNil(r *http.Request) *uuid.UUID {
	id, err := auth.FromContext(r.Context())
	if err != nil || id == nil {
		return nil
	}
	return id.TenantID
}

type idempotencyRow struct {
	status         string
	requestHash    []byte
	responseStatus int
	responseBody   []byte
	responseHdr    http.Header
}

// claim tries to INSERT a fresh in_flight row. Uses INSERT ...
// ON CONFLICT DO NOTHING RETURNING so we get an unambiguous signal:
// rows back = we inserted; no rows back = the unique constraint
// rejected our insert and a sibling already owns the key. After a
// sibling-rejection we SELECT to read the sibling's state.
//
// Returns:
//   (nil,    true, nil) → fresh insert; caller runs the handler.
//   (existing, false, nil) → sibling owns the row; caller replays
//                            its cached response or short-circuits
//                            as in-flight/conflict.
func claim(ctx context.Context, pool *pgxpool.Pool, tenantID *uuid.UUID, key string, hash []byte) (*idempotencyRow, bool, error) {
	// Phase 1: attempt insert. RETURNING tenant_id makes us check
	// whether anything came back without parsing the row.
	var inserted bool
	rows, err := pool.Query(ctx, `
		INSERT INTO idempotency_keys(tenant_id, key, request_hash, status)
		VALUES ($1, $2, $3, 'in_flight')
		ON CONFLICT DO NOTHING
		RETURNING key`,
		tenantID, key, hash)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		inserted = true
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, false, rows.Err()
	}
	if inserted {
		return nil, true, nil
	}

	// Phase 2: sibling owns the row — read its state.
	row := &idempotencyRow{}
	var hdrJSON []byte
	var respStatus *int
	if err := pool.QueryRow(ctx, `
		SELECT status, request_hash, response_status, response_body, response_headers
		  FROM idempotency_keys
		 WHERE COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid) =
		       COALESCE($1, '00000000-0000-0000-0000-000000000000'::uuid)
		   AND key = $2`,
		tenantID, key).
		Scan(&row.status, &row.requestHash, &respStatus, &row.responseBody, &hdrJSON); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Sibling deleted the row between our INSERT and our
			// SELECT (sweep cron, manual purge). Treat as fresh.
			return nil, true, nil
		}
		return nil, false, err
	}
	if respStatus != nil {
		row.responseStatus = *respStatus
	}
	if len(hdrJSON) > 0 {
		var hdrMap map[string][]string
		if err := json.Unmarshal(hdrJSON, &hdrMap); err == nil {
			row.responseHdr = http.Header(hdrMap)
		}
	}
	return row, false, nil
}

func finalize(ctx context.Context, pool *pgxpool.Pool, tenantID *uuid.UUID, key string, cap *captureWriter) {
	hdrJSON, _ := json.Marshal(map[string][]string(cap.header))
	_, _ = pool.Exec(ctx, `
		UPDATE idempotency_keys
		   SET status = 'complete',
		       response_status = $3,
		       response_body = $4,
		       response_headers = $5,
		       completed_at = now()
		 WHERE COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid) =
		       COALESCE($1, '00000000-0000-0000-0000-000000000000'::uuid)
		   AND key = $2`,
		tenantID, key, cap.statusCode, cap.body.Bytes(), hdrJSON)
}

// replay writes the cached headers + status + body back to w.
func replay(w http.ResponseWriter, row *idempotencyRow) {
	for k, vs := range row.responseHdr {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Idempotent-Replay", "true")
	if row.responseStatus == 0 {
		row.responseStatus = http.StatusOK
	}
	w.WriteHeader(row.responseStatus)
	_, _ = w.Write(row.responseBody)
}

// captureWriter remembers the response so finalize can persist it
// while also writing it to the real ResponseWriter.
type captureWriter struct {
	http.ResponseWriter
	body       *bytes.Buffer
	header     http.Header
	statusCode int
	headerSent bool
}

func (c *captureWriter) Header() http.Header {
	// Surface the real headers so handlers can read what they've
	// already set. Mirror writes into our cache via WriteHeader/Write.
	return c.ResponseWriter.Header()
}

func (c *captureWriter) WriteHeader(status int) {
	if c.headerSent {
		return
	}
	c.statusCode = status
	// Snapshot headers at WriteHeader time so finalize can persist
	// exactly what went on the wire.
	for k, vs := range c.ResponseWriter.Header() {
		cp := make([]string, len(vs))
		copy(cp, vs)
		c.header[k] = cp
	}
	c.headerSent = true
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(b []byte) (int, error) {
	if !c.headerSent {
		c.WriteHeader(http.StatusOK)
	}
	c.body.Write(b)
	return c.ResponseWriter.Write(b)
}

// SweepIdempotencyKeys deletes expired rows. Returns the count
// purged. Intended for periodic invocation by the cron-runner.
func SweepIdempotencyKeys(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	tag, err := pool.Exec(ctx,
		`DELETE FROM idempotency_keys WHERE expires_at < now()`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
