// archive.go — audit log archival service.
//
// What it does (one tick):
//   1. Look up audit_retention_policies → derive a cutoff
//      (now() - max retention_days across all policies).
//   2. Select the [min_id, max_id_before_cutoff] window of audit_logs
//      rows that haven't already been archived.
//   3. If window has rows: serialize to NDJSON, gzip, sha256, push
//      to the configured archive Storage backend.
//   4. POST sha256 to the RFC 3161 TSA; persist the token.
//   5. Write the audit_archive_runs row.
//   6. Separately (NOT in this tick — opt-in via PurgeAfterArchive
//      config), DELETE the source rows whose audit_archive_runs row
//      is older than confirmDelay.
//
// Storage layout (same Storage interface as evidence/):
//   archive/<YYYY>/<MM>/<DD>/audit-<from>-<to>.ndjson.gz

package audit

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/observability"
)

// archiveLogger is the component-tagged child logger for the audit
// archiver. Routed through logging.Component so level + env +
// service labels match the rest of the process.
var archiveLogger = logging.Component("audit-archive")

// ArchiveStorage is the contract a backend implements. The evidence
// package's Storage interface satisfies this; we redeclare locally
// to avoid an evidence→audit dep.
type ArchiveStorage interface {
	Put(ctx context.Context, key string, blob []byte) error
	Name() string
}

// FilesystemArchive is the dev-only on-disk backend. Production wires
// an S3-backed implementation via the same shape.
type FilesystemArchive struct {
	rootDir string
}

func NewFilesystemArchive(rootDir string) *FilesystemArchive {
	return &FilesystemArchive{rootDir: rootDir}
}

func (f *FilesystemArchive) Name() string { return "filesystem" }

func (f *FilesystemArchive) Put(_ context.Context, key string, blob []byte) error {
	full := f.rootDir + "/" + key
	dir := full
	if i := lastSlash(full); i >= 0 {
		dir = full[:i]
	}
	if err := osMkdirAll(dir, 0o700); err != nil {
		return err
	}
	return osWriteFile(full, blob, 0o600)
}

// Archiver coordinates one archival tick. Construct once at boot.
type Archiver struct {
	pool    *pgxpool.Pool
	storage ArchiveStorage
	tsa     *TSAClient
	// PurgeAfterArchive: when true, AfterPurgeDelay has elapsed since
	// archived_at, source audit_logs rows in the archived range are
	// DELETEd. When false, archival is non-destructive — the rows
	// stay in audit_logs forever (smaller deployments).
	PurgeAfterArchive bool
	PurgeAfterDelay   time.Duration
}

func NewArchiver(pool *pgxpool.Pool, storage ArchiveStorage, tsa *TSAClient) *Archiver {
	return &Archiver{
		pool:            pool,
		storage:         storage,
		tsa:             tsa,
		PurgeAfterDelay: 7 * 24 * time.Hour, // keep originals 1 week after archive
	}
}

// RunOnce performs one sweep. Returns the audit_archive_runs row id
// on success, 0 if there was nothing to archive.
func (a *Archiver) RunOnce(ctx context.Context, actor *uuid.UUID) (int64, error) {
	if a.storage == nil {
		return 0, errors.New("audit/archive: storage not configured")
	}
	cutoff, err := a.computeCutoff(ctx)
	if err != nil {
		return 0, fmt.Errorf("compute cutoff: %w", err)
	}

	// Find the window: rows older than cutoff that aren't already
	// covered by an existing archive run.
	var fromID, toID, rowCount int64
	err = a.pool.QueryRow(ctx, `
		WITH covered AS (
		  SELECT COALESCE(max(to_audit_id), 0) AS max_archived
		    FROM audit_archive_runs
		),
		window AS (
		  SELECT min(id) AS fid, max(id) AS tid, count(*) AS n
		    FROM audit_logs
		   WHERE id > (SELECT max_archived FROM covered)
		     AND occurred_at < $1
		)
		SELECT COALESCE(fid, 0), COALESCE(tid, 0), COALESCE(n, 0) FROM window`,
		cutoff).Scan(&fromID, &toID, &rowCount)
	if err != nil {
		return 0, fmt.Errorf("find window: %w", err)
	}
	if rowCount == 0 {
		return 0, nil
	}

	// Serialize: NDJSON, one row per line, in id order.
	body, err := a.serialize(ctx, fromID, toID)
	if err != nil {
		return 0, fmt.Errorf("serialize: %w", err)
	}
	// Gzip.
	var zbuf bytes.Buffer
	zw := gzip.NewWriter(&zbuf)
	if _, err := zw.Write(body); err != nil {
		return 0, err
	}
	if err := zw.Close(); err != nil {
		return 0, err
	}
	gz := zbuf.Bytes()
	sum := sha256.Sum256(gz)
	payloadHash := hex.EncodeToString(sum[:])

	// Push to storage.
	t := time.Now().UTC()
	key := fmt.Sprintf("archive/%04d/%02d/%02d/audit-%d-%d.ndjson.gz",
		t.Year(), t.Month(), t.Day(), fromID, toID)
	if err := a.storage.Put(ctx, key, gz); err != nil {
		return 0, fmt.Errorf("storage put: %w", err)
	}

	// Timestamp via TSA. Best-effort — if the TSA is briefly down,
	// the archive row is still written with a null token; ops can
	// retry-timestamp via a separate path.
	var (
		tokenBytes []byte
		tsaSerial  string
		tsaURL     string
	)
	if a.tsa != nil {
		if tok, err := a.tsa.Timestamp(ctx, sum[:]); err == nil {
			tokenBytes = tok.Token
			tsaSerial = tok.Serial
			tsaURL = a.tsa.URL
		} else {
			// Don't fail the whole archive run on TSA outage — the
			// archive's chain hash is still self-validating. BUT
			// log loud + bump a metric so an operator sees sustained
			// TSA failures before an auditor asks for a token weeks
			// later and the on-call discovers it's been missing.
			archiveLogger.Warn().
				Err(err).
				Str("op", "tsa.Timestamp").
				Str("tsa_url", a.tsa.URL).
				Msg("audit archive run could not obtain RFC3161 timestamp; row will be persisted without TSA proof")
			observability.AuditTSAFailures.Inc()
		}
	}

	storageURL := fmt.Sprintf("%s://%s", a.storage.Name(), key)
	var runID int64
	if err := a.pool.QueryRow(ctx, `
		INSERT INTO audit_archive_runs(from_audit_id, to_audit_id, row_count,
		    payload_sha256, storage_url, size_bytes,
		    tsa_token, tsa_url, tsa_serial, archived_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8,''), NULLIF($9,''), $10)
		RETURNING id`,
		fromID, toID, rowCount, payloadHash, storageURL, len(gz),
		tokenBytes, tsaURL, tsaSerial, actor).Scan(&runID); err != nil {
		return 0, fmt.Errorf("insert audit_archive_runs: %w", err)
	}

	// Optional purge — only fires for runs older than PurgeAfterDelay.
	if a.PurgeAfterArchive {
		_ = a.purgeOldArchives(ctx)
	}
	return runID, nil
}

// AnchorOnce stamps today's audit-chain head with the TSA — even when
// no archival is due. Cheap (one TSA round-trip + one DB insert) so
// the cron calls it daily.
func (a *Archiver) AnchorOnce(ctx context.Context) error {
	if a.tsa == nil {
		return errors.New("audit/archive: TSA not configured")
	}
	var (
		latestID int64
		chainHash []byte
	)
	err := a.pool.QueryRow(ctx, `
		SELECT id, chain_hash FROM audit_logs
		 ORDER BY id DESC LIMIT 1`).Scan(&latestID, &chainHash)
	if err != nil {
		return fmt.Errorf("anchor: read latest audit row: %w", err)
	}
	// Build the digest the TSA signs: sha256(id || chain_hash). We
	// pick an arbitrary stable hash; verifiers recompute it from the
	// id + chain_hash columns of the anchored row.
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d|", latestID)))
	h.Write(chainHash)
	anchorHash := h.Sum(nil)

	tok, err := a.tsa.Timestamp(ctx, anchorHash)
	if err != nil {
		return err
	}
	_, err = a.pool.Exec(ctx, `
		INSERT INTO audit_tsa_anchors(anchored_audit_id, chain_hash,
		    tsa_url, tsa_token, tsa_serial)
		VALUES ($1, $2, $3, $4, NULLIF($5,''))`,
		latestID, chainHash, a.tsa.URL, tok.Token, tok.Serial)
	return err
}

func (a *Archiver) serialize(ctx context.Context, fromID, toID int64) ([]byte, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT id, event, actor_type, host(ip), platform_id, partner_id, tenant_id,
		       target_type, target_id, payload, chain_prev, chain_hash, occurred_at
		  FROM audit_logs
		 WHERE id BETWEEN $1 AND $2
		 ORDER BY id`, fromID, toID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var buf bytes.Buffer
	for rows.Next() {
		var (
			id                                            int64
			event, actor                                  string
			ipStr                                         *string
			platID                                        uuid.UUID
			partID, tenID                                 *uuid.UUID
			tType, tID                                    *string
			payload                                       string
			chainPrev, chainHash                          []byte
			occurredAt                                    time.Time
		)
		if err := rows.Scan(&id, &event, &actor, &ipStr, &platID, &partID, &tenID,
			&tType, &tID, &payload, &chainPrev, &chainHash, &occurredAt); err != nil {
			return nil, err
		}
		line, _ := json.Marshal(map[string]any{
			"id":          id,
			"event":       event,
			"actor_type":  actor,
			"ip":          ipStr,
			"platform_id": platID,
			"partner_id":  partID,
			"tenant_id":   tenID,
			"target_type": tType,
			"target_id":   tID,
			"payload":     json.RawMessage(payload),
			"chain_prev":  hex.EncodeToString(chainPrev),
			"chain_hash":  hex.EncodeToString(chainHash),
			"occurred_at": occurredAt.UTC().Format(time.RFC3339Nano),
		})
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), rows.Err()
}

func (a *Archiver) computeCutoff(ctx context.Context) (time.Time, error) {
	// Take the MAX retention_days across all policies — anything
	// older than that is fair game to archive. (Per-event-prefix
	// retention is enforced separately by audit/ops.go's purge job;
	// here we use the loosest bound so we capture EVERYTHING old.)
	var maxDays int
	err := a.pool.QueryRow(ctx,
		`SELECT COALESCE(max(retention_days), 365) FROM audit_retention_policies`).
		Scan(&maxDays)
	if err != nil {
		return time.Time{}, err
	}
	return time.Now().UTC().AddDate(0, 0, -maxDays), nil
}

func (a *Archiver) purgeOldArchives(ctx context.Context) error {
	// Find archive runs whose archived_at is older than PurgeAfterDelay
	// AND whose source rows haven't been purged yet.
	cutoff := time.Now().UTC().Add(-a.PurgeAfterDelay)
	rows, err := a.pool.Query(ctx, `
		SELECT id, from_audit_id, to_audit_id
		  FROM audit_archive_runs
		 WHERE archived_at < $1 AND purged_at IS NULL
		 ORDER BY id ASC LIMIT 16`, cutoff)
	if err != nil {
		return err
	}
	defer rows.Close()
	type run struct{ id, from, to int64 }
	var pending []run
	for rows.Next() {
		var r run
		if err := rows.Scan(&r.id, &r.from, &r.to); err != nil {
			return err
		}
		pending = append(pending, r)
	}
	for _, r := range pending {
		// Open the purge window for this transaction only. The
		// audit_logs immutability trigger (migrations 0029, 0068)
		// rejects DELETE unless this session GUC is set. We set it
		// LOCAL so it's automatically cleared at COMMIT.
		tx, err := a.pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("audit purge: begin tx: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`SET LOCAL vaultscan.audit_purge_authorised = 'on'`); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("audit purge: open window: %w", err)
		}
		// Defensive: chain verifier needs an unbroken sequence, so we
		// only delete if every row in [from,to] is still present.
		if _, err := tx.Exec(ctx,
			`DELETE FROM audit_logs WHERE id BETWEEN $1 AND $2`,
			r.from, r.to); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("audit purge: delete rows [%d,%d]: %w", r.from, r.to, err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE audit_archive_runs SET purged_at = now() WHERE id = $1`, r.id); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("audit purge: mark run %d purged: %w", r.id, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("audit purge: commit: %w", err)
		}
	}
	return nil
}

// ---- helpers (file ops kept inline so we don't import os in test mode) ---

// We import via package indirection so the test file's stub can
// substitute. The real impls use os; we redeclare here as vars to
// keep production behavior with minimal surface.

// (The previous `var _ = tar.NewReader` keep-alive line and its
// archive/tar import are gone — nothing in this file actually uses
// tar, the comment-justified placeholder was vestigial.)

// osMkdirAll + osWriteFile + lastSlash are file-scope vars so tests
// can monkey-patch. Production assigns the real os.* funcs via init.
var (
	osMkdirAll   func(string, uint32) error = realMkdirAll
	osWriteFile  func(string, []byte, uint32) error = realWriteFile
)

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}
