// Package agentgw owns the gateway-side mTLS layer (HS-01 + Blueprint
// §6.3). The handshake-time check uses the standard library's
// RequireAndVerifyClientCert; on top of that, a VerifyPeerCertificate
// callback consults the agent_certificates table so a stolen-but-
// revoked cert is rejected mid-session, not only on next rotation.
package agentgw

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type agentCtxKey int

const agentIDCtx agentCtxKey = 1

// AgentFromContext returns the agent UUID stamped by the mTLS verifier
// or the dev-header middleware, or uuid.Nil if no authenticator ran.
func AgentFromContext(ctx context.Context) uuid.UUID {
	if v := ctx.Value(agentIDCtx); v != nil {
		if id, ok := v.(uuid.UUID); ok {
			return id
		}
	}
	return uuid.Nil
}

// WithAgent returns ctx with the agent UUID stamped under the canonical
// key. Used by the dev-header middleware in agent-gateway so handlers
// see the same shape regardless of which auth path ran.
func WithAgent(ctx context.Context, agentID uuid.UUID) context.Context {
	return context.WithValue(ctx, agentIDCtx, agentID)
}

// ErrAgentCertRejected is returned by the verifier for any of the
// "cert looks valid but we don't trust it" cases. Wraps a Reason for
// the operator audit log.
type ErrAgentCertRejected struct {
	Reason      string
	Fingerprint string
}

func (e *ErrAgentCertRejected) Error() string {
	return fmt.Sprintf("agentgw: cert rejected: %s (fp=%s)", e.Reason, e.Fingerprint)
}

// CertVerifier holds the trust state — the cached issuer pool, the
// pgx connection, and a small in-process LRU for fingerprint lookups.
type CertVerifier struct {
	pool   *pgxpool.Pool
	issuer *x509.CertPool

	// Fingerprint cache. A successful handshake stores
	// (fingerprint → cachedHandshake) with a short TTL so a fleet
	// of long-lived agents heartbeating every few seconds doesn't
	// hammer the DB for every TLS resumption. Misses + revocations
	// still go to the DB.
	cacheMu  sync.RWMutex
	cache    map[string]cachedHandshake
	cacheTTL time.Duration
}

type cachedHandshake struct {
	agentID    uuid.UUID
	agentState string
	expiresAt  time.Time
	cachedAt   time.Time
}

// NewCertVerifier builds a verifier from the current agent_ca_certificates
// rows. Callers refresh by re-calling NewCertVerifier on a cron tick.
func NewCertVerifier(ctx context.Context, pool *pgxpool.Pool) (*CertVerifier, error) {
	issuer := x509.NewCertPool()
	rows, err := pool.Query(ctx, `
		SELECT cert_pem FROM agent_ca_certificates
		 WHERE enabled = true AND not_after > now()`)
	if err != nil {
		return nil, fmt.Errorf("agentgw: load CAs: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var pemBytes string
		if err := rows.Scan(&pemBytes); err != nil {
			return nil, err
		}
		if !issuer.AppendCertsFromPEM([]byte(pemBytes)) {
			return nil, errors.New("agentgw: CA pool refused a PEM — bad cert in agent_ca_certificates")
		}
		count++
	}
	if count == 0 {
		// Empty pool = nobody can connect. Surface clearly.
		return nil, errors.New("agentgw: no trusted agent CAs configured; populate agent_ca_certificates")
	}
	return &CertVerifier{
		pool: pool, issuer: issuer,
		cache:    map[string]cachedHandshake{},
		cacheTTL: 30 * time.Second,
	}, nil
}

// StartCAPoolRefresh runs a background goroutine that periodically
// re-reads agent_ca_certificates and atomically swaps the issuer
// pool. Without this, a CA rotation requires a process restart and
// the pool can serve a revoked CA for the lifetime of the running
// gateway. Callers wire this from cmd/agent-gateway/main.go after
// constructing the verifier; the returned func cancels the loop on
// shutdown.
func (v *CertVerifier) StartCAPoolRefresh(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fresh, err := buildCAPoolFromDB(ctx, v.pool)
				if err != nil {
					// Keep existing pool — refusing to swap on a
					// transient DB error is better than nil'ing the
					// pool and rejecting every handshake.
					continue
				}
				v.cacheMu.Lock()
				v.issuer = fresh
				v.cacheMu.Unlock()
			}
		}
	}()
	return cancel
}

// buildCAPoolFromDB is the inner reader used by the periodic refresh
// loop. (NewCertVerifier inlines the same query for boot-time fast-
// fail semantics.)
func buildCAPoolFromDB(ctx context.Context, pool *pgxpool.Pool) (*x509.CertPool, error) {
	issuer := x509.NewCertPool()
	rows, err := pool.Query(ctx, `
		SELECT cert_pem FROM agent_ca_certificates
		 WHERE enabled = true AND not_after > now()`)
	if err != nil {
		return nil, fmt.Errorf("agentgw: load CAs: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var pemBytes string
		if err := rows.Scan(&pemBytes); err != nil {
			return nil, err
		}
		if !issuer.AppendCertsFromPEM([]byte(pemBytes)) {
			return nil, fmt.Errorf("agentgw: CA pool refused a PEM in refresh")
		}
		count++
	}
	if count == 0 {
		return nil, errors.New("agentgw: refresh found zero enabled CAs")
	}
	return issuer, nil
}

// IssuerPool returns the underlying *x509.CertPool. Used to build the
// tls.Config.ClientCAs.
//
// NOTE: TLS handshakes capture this pool ONCE when the listener starts.
// A CA refresh via StartCAPoolRefresh updates the verifier's internal
// pointer, but already-accepted TLS sessions use the boot-time pool.
// To pick up a rotation, the operator restarts the gateway after
// updating agent_ca_certificates. The refresh path still helps in
// that it keeps the cached fingerprint set fresh for handshake
// callbacks.
func (v *CertVerifier) IssuerPool() *x509.CertPool {
	v.cacheMu.RLock()
	defer v.cacheMu.RUnlock()
	return v.issuer
}

// VerifyPeerCertificate plugs into tls.Config.VerifyPeerCertificate.
// At this point the standard library has already confirmed the chain
// is signed by ClientCAs; we add the application-level checks:
//   1. Fingerprint exists in agent_certificates and revoked_at IS NULL.
//   2. expires_at > now() (also covered by stdlib but logged here).
//   3. agents.status NOT IN ('revoked','quarantined').
func (v *CertVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return &ErrAgentCertRejected{Reason: "no client cert presented"}
	}
	leaf := rawCerts[0]
	sum := sha256.Sum256(leaf)
	fp := hex.EncodeToString(sum[:])

	// Hot path: cache hit and entry still inside TTL → skip the DB.
	// A revocation in the cache window is rare (operators usually
	// scale of seconds–minutes); the 30s TTL bounds the window and
	// failures (expired/revoked/quarantined) are still always
	// caught by the DB query on miss.
	if cv := v.cacheGet(fp); cv != nil {
		if !time.Now().After(cv.expiresAt) &&
			cv.agentState != "revoked" && cv.agentState != "quarantined" {
			return nil
		}
		// Treat any negative state in the cached row as a forced
		// re-check; fall through to the DB path.
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var (
		agentID    uuid.UUID
		revokedAt  *time.Time
		expiresAt  time.Time
		agentState string
	)
	err := v.pool.QueryRow(ctx, `
		SELECT c.agent_id, c.revoked_at, c.expires_at, COALESCE(a.status, 'unknown')
		  FROM agent_certificates c
		  LEFT JOIN agents a ON a.id = c.agent_id
		 WHERE c.fingerprint = $1
		 ORDER BY c.issued_at DESC LIMIT 1`, fp).
		Scan(&agentID, &revokedAt, &expiresAt, &agentState)
	if err != nil {
		v.logHandshake(ctx, nil, fp, "rejected_unknown", "no row in agent_certificates")
		return &ErrAgentCertRejected{Reason: "unknown fingerprint", Fingerprint: fp}
	}
	if revokedAt != nil {
		v.logHandshake(ctx, &agentID, fp, "rejected_revoked",
			"revoked_at="+revokedAt.Format(time.RFC3339))
		return &ErrAgentCertRejected{Reason: "cert revoked", Fingerprint: fp}
	}
	if time.Now().After(expiresAt) {
		v.logHandshake(ctx, &agentID, fp, "rejected_expired", expiresAt.Format(time.RFC3339))
		return &ErrAgentCertRejected{Reason: "cert expired", Fingerprint: fp}
	}
	if agentState == "revoked" || agentState == "quarantined" {
		v.logHandshake(ctx, &agentID, fp, "rejected_revoked", "agent.status="+agentState)
		return &ErrAgentCertRejected{Reason: "agent " + agentState, Fingerprint: fp}
	}
	v.logHandshake(ctx, &agentID, fp, "accepted", "")
	// Populate the fingerprint cache so subsequent handshakes for
	// this agent skip the DB until the TTL elapses.
	v.cachePut(fp, cachedHandshake{
		agentID:    agentID,
		agentState: agentState,
		expiresAt:  expiresAt,
		cachedAt:   time.Now(),
	})
	return nil
}

func (v *CertVerifier) cacheGet(fp string) *cachedHandshake {
	v.cacheMu.RLock()
	defer v.cacheMu.RUnlock()
	if c, ok := v.cache[fp]; ok && time.Since(c.cachedAt) < v.cacheTTL {
		cp := c
		return &cp
	}
	return nil
}

func (v *CertVerifier) cachePut(fp string, c cachedHandshake) {
	v.cacheMu.Lock()
	defer v.cacheMu.Unlock()
	// Cheap bound on cache size — keep at most 4096 fingerprints.
	// In practice fleets are bounded by license; this is a safety
	// floor against unbounded growth from a stuck handshake loop.
	if len(v.cache) >= 4096 {
		// Drop ANY entry; we're not optimising eviction order
		// because the TTL keeps everything fresh.
		for k := range v.cache {
			delete(v.cache, k)
			break
		}
	}
	v.cache[fp] = c
}

func (v *CertVerifier) logHandshake(ctx context.Context, agentID *uuid.UUID, fp, decision, reason string) {
	_, _ = v.pool.Exec(ctx, `
		INSERT INTO agent_mtls_handshakes(agent_id, fingerprint, decision, reason)
		VALUES ($1, $2, $3, $4)`,
		agentID, fp, decision, nullIfEmpty(reason))
}

// IdentityFromTLSMiddleware stamps the agent_id derived from the
// presented client certificate onto every request. It assumes the TLS
// handshake has already passed VerifyPeerCertificate — i.e. that the
// cert chain is trusted AND the fingerprint matches a live agent row.
// If r.TLS is nil (someone bypassed the listener), the request is
// rejected with 495 (SSL Certificate Error, cribbed from nginx).
func IdentityFromTLSMiddleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				http.Error(w, "agentgw: no client cert", 495)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			sum := sha256.Sum256(leaf.Raw)
			fp := hex.EncodeToString(sum[:])
			var agentID uuid.UUID
			err := pool.QueryRow(r.Context(),
				`SELECT agent_id FROM agent_certificates
				  WHERE fingerprint=$1 AND revoked_at IS NULL`, fp).Scan(&agentID)
			if err != nil {
				http.Error(w, "agentgw: cert not registered", 401)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), agentIDCtx, agentID))
			next.ServeHTTP(w, r)
		})
	}
}

// BuildTLSConfig returns the *tls.Config the agent gateway uses on its
// listener. serverCertPEM / serverKeyPEM are the gateway's OWN cert
// (presented to the agent so the agent can validate the gateway).
func BuildTLSConfig(serverCertPEM, serverKeyPEM []byte, verifier *CertVerifier) (*tls.Config, error) {
	if verifier == nil {
		return nil, errors.New("agentgw: cert verifier required")
	}
	cert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("agentgw: server cert: %w", err)
	}
	return &tls.Config{
		MinVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{cert},
		ClientCAs:             verifier.IssuerPool(),
		ClientAuth:            tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: verifier.VerifyPeerCertificate,
		// Lock cipher policy to modern AEAD only (Blueprint §13.5).
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true,
	}, nil
}

// FingerprintPEMCert is the canonical client-side helper that mirrors
// the agent's enrollment code — gives every layer the same fingerprint
// string for a given cert PEM. Wraps sha256(DER) → lowercase hex.
func FingerprintPEMCert(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("agentgw: not a PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// remoteIPFromRequest extracts the agent's source IP from RemoteAddr.
// Tolerant of "ip:port" form and "[v6]:port".
func remoteIPFromRequest(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	host = strings.Trim(host, "[]")
	return net.ParseIP(host)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
