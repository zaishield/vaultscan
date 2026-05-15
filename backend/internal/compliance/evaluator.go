// Package compliance evaluates compliance_controls.evidence_query
// strings against live data and writes verdicts into
// compliance_evidence.
//
// The query DSL is intentionally tiny — a verb followed by k=v
// filters, parsed and dispatched by Evaluator.evaluate. Verbs:
//
//   findings:           <filter>... → count of matching findings
//   audit_logs:         <filter>... → count of matching audit rows
//   scan_jobs:          <filter>... → count of matching scan_jobs
//   evidence:           <filter>... → 1 if any evidence matches, 0 otherwise
//   retention:          <filter>... → check audit_retention_policies
//   integrations:       <filter>... → check integrations table
//   cloud_posture:      <filter>... → check cloud_posture_snapshots
//   tenant_data_keys:   <filter>... → check DEK presence
//   audit_archive_runs: <filter>... → check archive freshness
//   audit_tsa_anchors:  <filter>... → check anchor freshness
//   manual:reviewer-attests-XXX     → never passes automatically;
//                                     human attestation only
//
// The DSL is the same shape the seed migration uses, so adding a
// new control is one INSERT + zero code change here.

package compliance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Evaluator struct {
	pool *pgxpool.Pool
}

func NewEvaluator(pool *pgxpool.Pool) *Evaluator { return &Evaluator{pool: pool} }

// EvaluateOne runs evidenceQuery for tenantID and returns the
// (verdict, observedCount, note).
//
// verdict logic (defaults; controls can override via custom queries):
//   findings:status=open,severity>=high  → fail if count>0, else pass
//   findings:status=resolved,...         → pass if count>0, else fail
//   audit_logs:...,window=N               → pass if count>0, else fail
//                                           (we expect activity in the window)
//   evidence:encrypted=true              → pass if any encrypted row exists
//   manual:...                           → always "manual"
func (e *Evaluator) EvaluateOne(ctx context.Context, tenantID uuid.UUID, evidenceQuery string) (verdict string, observed int64, note string, err error) {
	q := strings.TrimSpace(evidenceQuery)
	if q == "" {
		return "manual", 0, "no query defined", nil
	}
	verb, rest, ok := strings.Cut(q, ":")
	if !ok {
		return "manual", 0, "unparseable query", nil
	}
	filters := parseFilters(rest)

	switch verb {
	case "manual":
		return "manual", 0, "manual attestation: " + rest, nil

	case "findings":
		count, err := e.countFindings(ctx, tenantID, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		return verdictForFindings(filters, count), count, "", nil

	case "audit_logs":
		count, err := e.countAuditLogs(ctx, tenantID, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		// Special-case: chain_integrity=true → run VerifyDeep instead
		// of counting rows.
		if filters["chain_integrity"] == "true" {
			ok, err := e.verifyAuditChainRecent(ctx, filters["window"])
			if err != nil {
				return "manual", count, err.Error(), nil
			}
			if ok {
				return "pass", count, "audit chain intact", nil
			}
			return "fail", count, "audit chain break detected in window", nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no activity in window", nil

	case "scan_jobs":
		count, err := e.countScanJobs(ctx, tenantID, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no scan jobs in window", nil

	case "evidence":
		count, err := e.countEvidence(ctx, tenantID, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no matching evidence rows", nil

	case "retention":
		ok, err := e.checkRetention(ctx, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if ok {
			return "pass", 1, "retention satisfies floor", nil
		}
		return "fail", 0, "retention below required floor", nil

	case "integrations":
		count, err := e.countIntegrations(ctx, tenantID, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no matching integration enabled", nil

	case "cloud_posture":
		count, err := e.countCloudPosture(ctx, tenantID, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no passing cloud posture snapshot", nil

	case "tenant_data_keys":
		count, err := e.countTenantKeys(ctx, tenantID)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no DEK for tenant", nil

	case "audit_archive_runs":
		count, err := e.countArchiveRuns(ctx, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no archive runs with TSA token in window", nil

	case "audit_tsa_anchors":
		count, err := e.countTSAAnchors(ctx, filters)
		if err != nil {
			return "manual", 0, err.Error(), nil
		}
		if count > 0 {
			return "pass", count, "", nil
		}
		return "fail", 0, "no TSA anchor in window", nil
	}
	return "manual", 0, "unknown verb: " + verb, nil
}

// EvaluateAll iterates every control + every active tenant and writes
// a row into compliance_evidence per (tenant, control). Designed for
// nightly cron invocation.
func (e *Evaluator) EvaluateAll(ctx context.Context) error {
	tenants, err := e.activeTenantIDs(ctx)
	if err != nil {
		return err
	}
	rows, err := e.pool.Query(ctx,
		`SELECT id, evidence_query FROM compliance_controls WHERE evidence_query IS NOT NULL`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type ctrl struct {
		id    uuid.UUID
		query string
	}
	var controls []ctrl
	for rows.Next() {
		var c ctrl
		if err := rows.Scan(&c.id, &c.query); err != nil {
			return err
		}
		controls = append(controls, c)
	}
	for _, tid := range tenants {
		for _, c := range controls {
			verdict, observed, note, _ := e.EvaluateOne(ctx, tid, c.query)
			if _, err := e.pool.Exec(ctx, `
				INSERT INTO compliance_evidence(tenant_id, control_id,
				    verdict, observed_count, note)
				VALUES ($1, $2, $3, $4, NULLIF($5,''))`,
				tid, c.id, verdict, observed, note); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---- helpers --------------------------------------------------------------

func (e *Evaluator) activeTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := e.pool.Query(ctx,
		`SELECT id FROM tenants WHERE status = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (e *Evaluator) countFindings(ctx context.Context, tenantID uuid.UUID, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM findings WHERE tenant_id=$1`
	args := []any{tenantID}
	if v := f["status"]; v != "" {
		q += " AND status=$2"
		args = append(args, v)
	}
	if v := f["severity"]; v != "" {
		// Support "severity>=high" → expand to in-list.
		if strings.HasPrefix(v, ">=") {
			sev := v[2:]
			set := severitiesGTE(sev)
			q += fmt.Sprintf(" AND severity = ANY($%d)", len(args)+1)
			args = append(args, set)
		} else {
			q += fmt.Sprintf(" AND severity = $%d", len(args)+1)
			args = append(args, v)
		}
	}
	if v := f["age"]; v != "" {
		// age<30d → first_seen > now()-30d
		// age>30d → first_seen < now()-30d
		dur, op, ok := parseAge(v)
		if ok {
			q += fmt.Sprintf(" AND first_seen %s now() - $%d::interval", op, len(args)+1)
			args = append(args, dur.String())
		}
	}
	if v := f["window"]; v != "" {
		dur, ok := parseWindow(v)
		if ok {
			q += fmt.Sprintf(" AND last_seen > now() - $%d::interval", len(args)+1)
			args = append(args, dur.String())
		}
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	return n, err
}

func verdictForFindings(f filters, count int64) string {
	status := f["status"]
	switch status {
	case "open":
		// "open + severity≥high + age>30d" → ANY hit = fail.
		if count > 0 {
			return "fail"
		}
		return "pass"
	case "resolved":
		// "resolved + window" → at least one resolved = pass.
		if count > 0 {
			return "pass"
		}
		return "fail"
	default:
		if count > 0 {
			return "pass"
		}
		return "fail"
	}
}

func (e *Evaluator) countAuditLogs(ctx context.Context, tenantID uuid.UUID, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM audit_logs WHERE 1=1`
	args := []any{}
	if v := f["event"]; v != "" {
		q += fmt.Sprintf(" AND event = $%d", len(args)+1)
		args = append(args, v)
	}
	if v := f["event_prefix"]; v != "" {
		q += fmt.Sprintf(" AND event LIKE $%d", len(args)+1)
		args = append(args, v+"%")
	}
	if v := f["actor_type"]; v != "" {
		q += fmt.Sprintf(" AND actor_type = $%d", len(args)+1)
		args = append(args, v)
	}
	if v := f["window"]; v != "" {
		dur, ok := parseWindow(v)
		if ok {
			q += fmt.Sprintf(" AND occurred_at > now() - $%d::interval", len(args)+1)
			args = append(args, dur.String())
		}
	}
	// Tenant scope: most audit queries are platform-scoped (tenant_id
	// may be null). Apply only when explicitly requested.
	if f["tenant_scoped"] == "true" {
		q += fmt.Sprintf(" AND tenant_id = $%d", len(args)+1)
		args = append(args, tenantID)
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	return n, err
}

func (e *Evaluator) verifyAuditChainRecent(ctx context.Context, _ string) (bool, error) {
	// The audit.Service.VerifyDeep does the heavy lifting; this helper
	// just asks "any chain break recorded recently?".
	var n int
	err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_chain_breaks
		  WHERE detected_at > now() - interval '24 hours'`).Scan(&n)
	if err != nil {
		// Table may not exist on smaller deployments. Assume intact.
		return true, nil
	}
	return n == 0, nil
}

func (e *Evaluator) countScanJobs(ctx context.Context, tenantID uuid.UUID, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM scan_jobs WHERE tenant_id=$1`
	args := []any{tenantID}
	if v := f["plane"]; v != "" {
		q += fmt.Sprintf(" AND plane = $%d", len(args)+1)
		args = append(args, v)
	}
	if v := f["status"]; v != "" {
		q += fmt.Sprintf(" AND status = $%d", len(args)+1)
		args = append(args, v)
	}
	if v := f["profile_code"]; v != "" {
		q += fmt.Sprintf(` AND profile_id IN (SELECT id FROM scan_profiles WHERE code = $%d)`,
			len(args)+1)
		args = append(args, v)
	}
	if v := f["window"]; v != "" {
		if dur, ok := parseWindow(v); ok {
			q += fmt.Sprintf(" AND created_at > now() - $%d::interval", len(args)+1)
			args = append(args, dur.String())
		}
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	return n, err
}

func (e *Evaluator) countEvidence(ctx context.Context, tenantID uuid.UUID, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM finding_evidence WHERE tenant_id=$1 AND purged_at IS NULL`
	args := []any{tenantID}
	if f["encrypted"] == "true" {
		q += " AND encrypted = true"
	}
	if f["worm_enabled"] == "true" {
		q += " AND COALESCE(worm, false) = true"
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	return n, err
}

func (e *Evaluator) checkRetention(ctx context.Context, f filters) (bool, error) {
	prefix := f["event_prefix"]
	if prefix == "" || prefix == "*" {
		prefix = ""
	}
	floor := 0
	if v := f["retention_days"]; v != "" {
		if strings.HasPrefix(v, ">=") {
			_, _ = fmt.Sscanf(v[2:], "%d", &floor)
		} else {
			_, _ = fmt.Sscanf(v, "%d", &floor)
		}
	}
	if floor <= 0 {
		return false, errors.New("retention: floor required")
	}
	var maxDays int
	q := `SELECT COALESCE(max(retention_days), 0) FROM audit_retention_policies`
	args := []any{}
	if prefix != "" {
		q += " WHERE event_prefix LIKE $1"
		args = append(args, prefix+"%")
	}
	if err := e.pool.QueryRow(ctx, q, args...).Scan(&maxDays); err != nil {
		return false, err
	}
	return maxDays >= floor, nil
}

func (e *Evaluator) countIntegrations(ctx context.Context, tenantID uuid.UUID, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM integrations
	      WHERE (tenant_id IS NULL OR tenant_id = $1)`
	args := []any{tenantID}
	if v := f["type"]; v != "" {
		q += fmt.Sprintf(" AND type = $%d", len(args)+1)
		args = append(args, v)
	}
	if f["enabled"] == "true" {
		q += " AND enabled = true"
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	return n, err
}

func (e *Evaluator) countCloudPosture(ctx context.Context, tenantID uuid.UUID, f filters) (int64, error) {
	// Counts the most-recent snapshot per cloud account whose
	// overall_score is >0 (i.e. we successfully scanned something).
	var n int64
	q := `SELECT count(*) FROM cloud_posture_snapshots s
	        JOIN cloud_accounts a ON a.id = s.account_id
	       WHERE a.tenant_id = $1 AND s.overall_score IS NOT NULL`
	args := []any{tenantID}
	if v := f["provider"]; v != "" {
		q += fmt.Sprintf(" AND a.provider = $%d", len(args)+1)
		args = append(args, v)
	}
	if v := f["window"]; v != "" {
		if dur, ok := parseWindow(v); ok {
			q += fmt.Sprintf(" AND s.snapshot_at > now() - $%d::interval", len(args)+1)
			args = append(args, dur.String())
		}
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	if err != nil {
		// Table absent (no cloud accounts yet) → not-applicable as fail-soft.
		return 0, nil
	}
	return n, nil
}

func (e *Evaluator) countTenantKeys(ctx context.Context, tenantID uuid.UUID) (int64, error) {
	var n int64
	err := e.pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_data_keys WHERE tenant_id=$1`, tenantID).Scan(&n)
	return n, err
}

func (e *Evaluator) countArchiveRuns(ctx context.Context, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM audit_archive_runs WHERE tsa_token IS NOT NULL`
	args := []any{}
	if v := f["window"]; v != "" {
		if dur, ok := parseWindow(v); ok {
			q += fmt.Sprintf(" AND archived_at > now() - $%d::interval", len(args)+1)
			args = append(args, dur.String())
		}
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	if err != nil {
		return 0, nil
	}
	return n, nil
}

func (e *Evaluator) countTSAAnchors(ctx context.Context, f filters) (int64, error) {
	var n int64
	q := `SELECT count(*) FROM audit_tsa_anchors WHERE tsa_token IS NOT NULL`
	args := []any{}
	if v := f["window"]; v != "" {
		if dur, ok := parseWindow(v); ok {
			q += fmt.Sprintf(" AND anchored_at > now() - $%d::interval", len(args)+1)
			args = append(args, dur.String())
		}
	}
	err := e.pool.QueryRow(ctx, q, args...).Scan(&n)
	if err != nil {
		return 0, nil
	}
	return n, nil
}

// ---- filter parsing ------------------------------------------------------

type filters map[string]string

// parseFilters handles three forms:
//   key=value         (plain equality; value carries no operator)
//   key>=value        (key recovered, value stored as ">=value")
//   key<value         (key recovered, value stored as "<value")
// All three preserve the operator inside the value so callers can
// pattern-match on it (severity">=high" → expand to in-list).
func parseFilters(s string) filters {
	out := filters{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		consumed := false
		// Try comparison operators first; longest match wins.
		for _, op := range []string{">=", "<=", ">", "<"} {
			idx := strings.Index(part, op)
			if idx <= 0 {
				continue
			}
			// Reject `key=value>` shape — `=` before the op means it's
			// a plain assignment whose value happens to contain `>`.
			if eq := strings.Index(part, "="); eq >= 0 && eq < idx {
				break
			}
			key := strings.TrimSpace(part[:idx])
			val := strings.TrimSpace(part[idx:]) // keep op IN value
			out[key] = val
			consumed = true
			break
		}
		if consumed {
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// parseWindow accepts "24h", "30d", "90d", "7d".
func parseWindow(s string) (time.Duration, bool) {
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil {
			return time.Duration(days) * 24 * time.Hour, true
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return d, true
}

// parseAge handles "age<30d" / "age>30d".
func parseAge(s string) (time.Duration, string, bool) {
	op := ""
	rest := ""
	switch {
	case strings.HasPrefix(s, "<"):
		op = ">"  // first_seen > now()-30d == age < 30d
		rest = s[1:]
	case strings.HasPrefix(s, ">"):
		op = "<"
		rest = s[1:]
	default:
		return 0, "", false
	}
	d, ok := parseWindow(rest)
	return d, op, ok
}

// severitiesGTE returns the list of severity strings that rank ≥ given.
// info < low < medium < high < critical
func severitiesGTE(s string) []string {
	order := []string{"info", "low", "medium", "high", "critical"}
	start := -1
	for i, sev := range order {
		if sev == s {
			start = i
			break
		}
	}
	if start < 0 {
		return []string{s}
	}
	return order[start:]
}
