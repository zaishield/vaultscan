package agents

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/google/uuid"
)

// ------------------ CSR-based cert rotation ----------------------------------

// SubmitCSR parses a PKCS#10 CSR from the agent, signs it with the platform
// CA, persists the new certificate, marks the previous certificate revoked,
// and links the CSR row to the issued cert. Blueprint §28.3 (cert rotation).
// Returns the issued cert PEM the agent should install + its serial.
func (s *Service) SubmitCSR(ctx context.Context, agentID uuid.UUID, csrPEM string, ca *CA) (string, string, error) {
	if ca == nil {
		return "", "", errors.New("agents: CA not configured")
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", "", errors.New("agents: csr_pem not a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("agents: parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", fmt.Errorf("agents: csr signature invalid: %w", err)
	}

	csrSum := sha256.Sum256(block.Bytes)
	csrHash := hex.EncodeToString(csrSum[:])

	// Insert the CSR row first so we can attach the issued cert id.
	var csrID uuid.UUID
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_csr_requests(agent_id, csr_pem, csr_sha256, status)
		VALUES ($1, $2, $3, 'pending')
		RETURNING id`, agentID, csrPEM, csrHash).Scan(&csrID); err != nil {
		return "", "", err
	}

	// Mint the cert.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "agent-" + agentID.String(),
			Organization: []string{"ZAISHIELD VAULTSCAN"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		_, _ = s.pool.Exec(ctx,
			`UPDATE agent_csr_requests SET status='rejected', rejection_reason=$2, decided_at=now()
			 WHERE id=$1`, csrID, "ca_sign_failed: "+err.Error())
		return "", "", fmt.Errorf("agents: sign cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	fp := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(fp[:])
	serialHex := hex.EncodeToString(serial.Bytes())

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx)

	// Revoke prior live certs.
	if _, err := tx.Exec(ctx, `
		UPDATE agent_certificates SET revoked_at=now()
		 WHERE agent_id=$1 AND revoked_at IS NULL`, agentID); err != nil {
		return "", "", err
	}
	var newCertID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO agent_certificates(agent_id, serial, fingerprint, pem, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		agentID, serialHex, fingerprint, string(certPEM), tmpl.NotAfter).Scan(&newCertID); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agents SET cert_status='issued', cert_expires_at=$2, updated_at=now()
		 WHERE id=$1`, agentID, tmpl.NotAfter); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE agent_csr_requests
		   SET status='issued', issued_cert_id=$2, decided_at=now()
		 WHERE id=$1`, csrID, newCertID); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}
	return string(certPEM), fingerprint, nil
}

// CA wraps the platform's internal agent-signing CA. In production it's
// loaded from a Vault PKI mount; tests pass a self-signed in-process CA.
type CA struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// NewSelfSignedCA returns a fresh in-process CA suitable for tests.
func NewSelfSignedCA() (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "vaultscan-agent-ca", Organization: []string{"ZAISHIELD"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// ------------------ Telemetry rollups ----------------------------------------

// RolledTelemetry summarises a 5-minute window.
type RolledTelemetry struct {
	BucketStart time.Time `json:"bucket_start"`
	Samples     int       `json:"samples"`
	CPUAvg      float64   `json:"cpu_avg"`
	CPUPeak     float64   `json:"cpu_peak"`
	MemAvg      float64   `json:"memory_avg"`
	MemPeak     float64   `json:"memory_peak"`
	QueuePeak   int       `json:"queue_peak"`
}

// RollupTelemetry computes 5-minute aggregates from agent_heartbeats for
// an agent over the requested range and upserts them into the rollup
// table. Designed for periodic cron invocation.
func (s *Service) RollupTelemetry(ctx context.Context, agentID uuid.UUID, since, until time.Time) (int, error) {
	tag, err := s.pool.Exec(ctx, `
		INSERT INTO agent_telemetry_rollups
		   (agent_id, bucket_start, bucket_minutes, samples,
		    cpu_avg, cpu_peak, memory_avg, memory_peak, disk_avg, queue_peak)
		SELECT $1,
		       date_trunc('minute', received_at)
		         - (extract(minute from received_at)::int % 5) * interval '1 minute',
		       5,
		       count(*)::int,
		       round(avg(cpu_percent)::numeric, 2),
		       round(max(cpu_percent)::numeric, 2),
		       round(avg(memory_percent)::numeric, 2),
		       round(max(memory_percent)::numeric, 2),
		       round(avg(disk_percent)::numeric, 2),
		       coalesce(max(queue_depth), 0)
		  FROM agent_heartbeats
		 WHERE agent_id=$1 AND received_at >= $2 AND received_at < $3
		 GROUP BY 2
		ON CONFLICT (agent_id, bucket_start, bucket_minutes) DO UPDATE
		   SET samples     = EXCLUDED.samples,
		       cpu_avg     = EXCLUDED.cpu_avg,
		       cpu_peak    = EXCLUDED.cpu_peak,
		       memory_avg  = EXCLUDED.memory_avg,
		       memory_peak = EXCLUDED.memory_peak,
		       disk_avg    = EXCLUDED.disk_avg,
		       queue_peak  = EXCLUDED.queue_peak`,
		agentID, since, until)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func (s *Service) ListTelemetry(ctx context.Context, agentID uuid.UUID, since time.Time) ([]RolledTelemetry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT bucket_start, samples, cpu_avg, cpu_peak,
		       memory_avg, memory_peak, queue_peak
		  FROM agent_telemetry_rollups
		 WHERE agent_id=$1 AND bucket_start >= $2
		 ORDER BY bucket_start`,
		agentID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RolledTelemetry
	for rows.Next() {
		var r RolledTelemetry
		if err := rows.Scan(&r.BucketStart, &r.Samples, &r.CPUAvg, &r.CPUPeak,
			&r.MemAvg, &r.MemPeak, &r.QueuePeak); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ------------------ Signed update bundles -----------------------------------

type UpdateBundleManifest struct {
	TargetVersion   string `json:"target_version"`
	DownloadURL     string `json:"download_url"`
	BundleSHA256    string `json:"bundle_sha256"`
	MinFromVersion  string `json:"min_from_version,omitempty"`
	IssuedAt        string `json:"issued_at"`
}

// CanonicalManifestBytes returns the deterministic byte form the signature
// covers — json.Marshal already serialises map keys deterministically but
// using a struct guarantees field order.
func CanonicalManifestBytes(m UpdateBundleManifest) []byte {
	b, _ := json.Marshal(m)
	return b
}

// PublishBundle stores a manifest + its RSA-PSS signature. The signature is
// produced by the cloud-CA private key (same key that signs scan jobs in
// scanorch.Signer); verification uses the matching public key.
func (s *Service) PublishBundle(ctx context.Context, m UpdateBundleManifest, sigB64, keyID, notes string) (uuid.UUID, error) {
	if m.TargetVersion == "" || m.DownloadURL == "" || m.BundleSHA256 == "" {
		return uuid.Nil, errors.New("agents: bundle manifest fields missing")
	}
	mj, _ := json.Marshal(m)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_update_bundles
		    (target_version, download_url, bundle_sha256, manifest_json,
		     manifest_signature, signing_key_id, min_from_version, notes)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
		RETURNING id`,
		m.TargetVersion, m.DownloadURL, m.BundleSHA256, mj,
		sigB64, keyID, nullIfEmpty(m.MinFromVersion), nullIfEmpty(notes)).
		Scan(&id)
	return id, err
}

type OfferedBundle struct {
	ID              uuid.UUID            `json:"id"`
	Manifest        UpdateBundleManifest `json:"manifest"`
	Signature       string               `json:"signature_b64"`
	SigningKeyID    string               `json:"signing_key_id"`
}

// OfferUpdate returns the newest applicable bundle for an agent at
// `currentVersion`, respecting MinFromVersion gating + rollout_paused.
func (s *Service) OfferUpdate(ctx context.Context, agentID uuid.UUID, currentVersion string) (*OfferedBundle, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, target_version, download_url, bundle_sha256, manifest_json,
		       manifest_signature, signing_key_id, COALESCE(min_from_version, '')
		  FROM agent_update_bundles
		 WHERE rollout_paused = false
		 ORDER BY rollout_started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id          uuid.UUID
			target, url, sha, sig, key, minFrom string
			mj          []byte
		)
		if err := rows.Scan(&id, &target, &url, &sha, &mj, &sig, &key, &minFrom); err != nil {
			return nil, err
		}
		if target == currentVersion {
			continue
		}
		if minFrom != "" && currentVersion != "" && versionLess(currentVersion, minFrom) {
			continue
		}
		var manifest UpdateBundleManifest
		_ = json.Unmarshal(mj, &manifest)
		// Record the offering.
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO agent_update_assignments(agent_id, bundle_id)
			VALUES ($1, $2)
			ON CONFLICT (agent_id, bundle_id) DO NOTHING`, agentID, id)
		return &OfferedBundle{ID: id, Manifest: manifest, Signature: sig, SigningKeyID: key}, nil
	}
	return nil, nil
}

// VerifyBundleSig checks the manifest signature against an RSA public key.
// Agents call this BEFORE touching the bundle bytes.
func VerifyBundleSig(manifestJSON []byte, sigB64 string, publicKey *rsa.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("agents: signature not base64: %w", err)
	}
	hashed := sha256.Sum256(manifestJSON)
	if err := rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], sig, nil); err != nil {
		return fmt.Errorf("agents: bundle signature rejected: %w", err)
	}
	return nil
}

// SignBundleManifest is a helper used by the publisher CLI / tests.
func SignBundleManifest(manifestJSON []byte, key *rsa.PrivateKey) (string, error) {
	hashed := sha256.Sum256(manifestJSON)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// versionLess is a tolerant semver-ish less-than: dotted decimals compared
// numerically component-by-component. Falls back to string compare for
// non-numeric segments.
func versionLess(a, b string) bool {
	pa, pb := splitVersion(a), splitVersion(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		ai, aOK := parseInt(pa[i])
		bi, bOK := parseInt(pb[i])
		if aOK && bOK {
			return ai < bi
		}
		return pa[i] < pb[i]
	}
	return len(pa) < len(pb)
}

func splitVersion(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == '.' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func parseInt(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}

// ------------------ Emergency-stop SLA ---------------------------------------

type EmergencyStop struct {
	ID         uuid.UUID `json:"id"`
	AgentID    uuid.UUID `json:"agent_id"`
	Reason     string    `json:"reason"`
	ArrivalTS  time.Time `json:"arrival_ts"`
	AckTS      *time.Time `json:"ack_ts,omitempty"`
	ResolvedTS *time.Time `json:"resolved_ts,omitempty"`
	SLAMs      *int       `json:"sla_ms,omitempty"`
	Scope      string     `json:"scope"`
}

// RequestEmergencyStop records the cloud-side intent. Caller (orchestrator)
// then publishes the EmergencyStopTriggered event the agent listens for.
func (s *Service) RequestEmergencyStop(ctx context.Context, agentID uuid.UUID, reason, scope string, actor *uuid.UUID) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_emergency_stops(agent_id, reason, requested_by, scope)
		VALUES ($1, $2, $3, COALESCE(NULLIF($4,''), 'agent'))
		RETURNING id`,
		agentID, reason, actor, scope).Scan(&id)
	return id, err
}

// AckEmergencyStop is invoked when the agent's next heartbeat carries the
// "emergency_stopped" flag. Computes SLA = ack - arrival.
func (s *Service) AckEmergencyStop(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agent_emergency_stops
		   SET ack_ts = COALESCE(ack_ts, now()),
		       sla_ms = COALESCE(sla_ms,
		           (EXTRACT(EPOCH FROM (now() - arrival_ts)) * 1000)::int)
		 WHERE id=$1`, id)
	return err
}

// LatestEmergencyStop returns the most recent pending (un-acked) stop for
// an agent so the next heartbeat handler can ack it.
func (s *Service) LatestEmergencyStop(ctx context.Context, agentID uuid.UUID) (*EmergencyStop, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, agent_id, reason, arrival_ts, ack_ts, resolved_ts, sla_ms, scope
		  FROM agent_emergency_stops
		 WHERE agent_id=$1
		 ORDER BY arrival_ts DESC LIMIT 1`, agentID)
	var e EmergencyStop
	if err := row.Scan(&e.ID, &e.AgentID, &e.Reason, &e.ArrivalTS,
		&e.AckTS, &e.ResolvedTS, &e.SLAMs, &e.Scope); err != nil {
		return nil, err
	}
	return &e, nil
}

// EmergencyStopSLAStats returns avg + p95 in milliseconds for an agent's
// emergency stops since `since`. Production target is < 30000ms.
type SLAStats struct {
	Count   int     `json:"count"`
	AvgMs   float64 `json:"avg_ms"`
	P95Ms   int     `json:"p95_ms"`
	BreachCount int `json:"breach_count"`   // count of stops > 30 seconds
}

func (s *Service) EmergencyStopSLAStats(ctx context.Context, agentID uuid.UUID, since time.Time) (SLAStats, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT sla_ms FROM agent_emergency_stops
		 WHERE agent_id=$1 AND arrival_ts >= $2 AND sla_ms IS NOT NULL
		 ORDER BY sla_ms`, agentID, since)
	if err != nil {
		return SLAStats{}, err
	}
	defer rows.Close()
	var samples []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return SLAStats{}, err
		}
		samples = append(samples, v)
	}
	if len(samples) == 0 {
		return SLAStats{}, nil
	}
	sort.Ints(samples)
	var sum, breach int
	for _, v := range samples {
		sum += v
		if v > 30000 {
			breach++
		}
	}
	p95idx := (len(samples) * 95) / 100
	if p95idx >= len(samples) {
		p95idx = len(samples) - 1
	}
	return SLAStats{
		Count:       len(samples),
		AvgMs:       float64(sum) / float64(len(samples)),
		P95Ms:       samples[p95idx],
		BreachCount: breach,
	}, nil
}
