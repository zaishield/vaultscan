// Package cloudposture implements §21 of the Blueprint — connect a
// customer's AWS/Azure/GCP account, run a CIS-baselined posture scan,
// and surface drift. The actual provider SDKs are loaded via an
// adapter interface so the package stays unit-testable.
package cloudposture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Service struct {
	pool     *pgxpool.Pool
	adapters map[string]ProviderAdapter
}

// ProviderAdapter is the contract a cloud-specific implementation
// satisfies. Each adapter knows how to authenticate against its
// provider (using credentials looked up via credential_ref) and
// produce a normalised []ControlResult.
type ProviderAdapter interface {
	Provider() string
	Scan(ctx context.Context, account CloudAccount) ([]ControlResult, error)
}

// CloudAccount is the in-memory representation of one tenant-owned
// cloud account.
type CloudAccount struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	Provider      string   // aws | azure | gcp
	AccountLabel  string
	ExternalID    string   // AWS account id, Azure subscription, GCP project
	CredentialRef string
	RoleARN       string
	Regions       []string
}

// ControlResult is the normalised output every adapter produces.
type ControlResult struct {
	ControlID   string         `json:"control_id"`   // CIS-AWS-1.5
	Title       string         `json:"title"`
	Status      string         `json:"status"`       // pass | fail | not_applicable | manual
	Severity    string         `json:"severity"`
	Resource    string         `json:"resource,omitempty"`
	Region      string         `json:"region,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	Remediation string         `json:"remediation,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
}

func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, adapters: map[string]ProviderAdapter{}}
}

// RegisterAdapter wires a provider implementation. cmd/api/main.go
// calls this for each provider whose SDK is compiled in.
func (s *Service) RegisterAdapter(a ProviderAdapter) {
	s.adapters[a.Provider()] = a
}

// ConnectAccount adds (or updates) a cloud_accounts row. The
// credential is stored as a reference; the actual creds live in the
// secrets backend.
type ConnectInput struct {
	TenantID      uuid.UUID
	Provider      string
	AccountLabel  string
	ExternalID    string
	CredentialRef string
	RoleARN       string
	Regions       []string
}

func (s *Service) ConnectAccount(ctx context.Context, in ConnectInput) (uuid.UUID, error) {
	if in.Provider == "" || in.ExternalID == "" {
		return uuid.Nil, errors.New("cloudposture: provider + external_id required")
	}
	regionsJSON, _ := json.Marshal(in.Regions)
	var id uuid.UUID
	err := s.pool.QueryRow(ctx, `
		INSERT INTO cloud_accounts(tenant_id, provider, account_label, external_id,
		    credential_ref, role_arn, regions)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6,''), $7::jsonb)
		ON CONFLICT (tenant_id, provider, external_id) DO UPDATE
		   SET account_label  = EXCLUDED.account_label,
		       credential_ref = EXCLUDED.credential_ref,
		       role_arn       = EXCLUDED.role_arn,
		       regions        = EXCLUDED.regions
		RETURNING id`,
		in.TenantID, in.Provider, in.AccountLabel, in.ExternalID,
		in.CredentialRef, in.RoleARN, regionsJSON).Scan(&id)
	return id, err
}

// Snapshot runs the adapter, persists results + computes drift
// against the previous snapshot.
func (s *Service) Snapshot(ctx context.Context, accountID uuid.UUID) (snapshotID uuid.UUID, err error) {
	acct, err := s.getAccount(ctx, accountID)
	if err != nil {
		return uuid.Nil, err
	}
	adapter, ok := s.adapters[acct.Provider]
	if !ok {
		return uuid.Nil, fmt.Errorf("cloudposture: no adapter registered for %s", acct.Provider)
	}
	results, err := adapter.Scan(ctx, acct)
	if err != nil {
		_, _ = s.pool.Exec(ctx,
			`UPDATE cloud_accounts SET last_error=$2 WHERE id=$1`, accountID, err.Error())
		return uuid.Nil, err
	}
	findingsJSON, _ := json.Marshal(results)
	br := scoreBreakdown(results)
	if err := s.pool.QueryRow(ctx, `
		INSERT INTO cloud_posture_snapshots(
		    account_id, findings, overall_score,
		    automated_count, manual_count, not_applicable_count,
		    total_count, coverage_percent)
		VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		accountID, findingsJSON, br.Score,
		br.AutomatedCount, br.ManualCount, br.NotApplicable,
		br.TotalCount, br.CoveragePercent).Scan(&snapshotID); err != nil {
		return uuid.Nil, err
	}
	if _, err := s.pool.Exec(ctx,
		`UPDATE cloud_accounts SET last_snapshot_at=now(), last_error=NULL WHERE id=$1`,
		accountID); err != nil {
		return uuid.Nil, err
	}
	if err := s.computeDrift(ctx, accountID, results); err != nil {
		return snapshotID, err
	}
	return snapshotID, nil
}

// LatestSnapshot returns the most recent snapshot for an account.
func (s *Service) LatestSnapshot(ctx context.Context, accountID uuid.UUID) ([]ControlResult, float64, error) {
	var raw []byte
	var score float64
	err := s.pool.QueryRow(ctx, `
		SELECT findings, overall_score FROM cloud_posture_snapshots
		 WHERE account_id = $1
		 ORDER BY snapshot_at DESC LIMIT 1`, accountID).Scan(&raw, &score)
	if err != nil {
		return nil, 0, err
	}
	var out []ControlResult
	_ = json.Unmarshal(raw, &out)
	return out, score, nil
}

// DriftSince returns drift events for an account since `since`.
type DriftEvent struct {
	ControlID     string    `json:"control_id"`
	Direction     string    `json:"direction"`
	PreviousState string    `json:"previous_state"`
	CurrentState  string    `json:"current_state"`
	DetectedAt    time.Time `json:"detected_at"`
}

func (s *Service) DriftSince(ctx context.Context, accountID uuid.UUID, since time.Time) ([]DriftEvent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT control_id, direction, previous_state, current_state, detected_at
		  FROM cloud_drift_events
		 WHERE account_id = $1 AND detected_at >= $2
		 ORDER BY detected_at DESC`, accountID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DriftEvent
	for rows.Next() {
		var d DriftEvent
		if err := rows.Scan(&d.ControlID, &d.Direction, &d.PreviousState,
			&d.CurrentState, &d.DetectedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ----- internals -----------------------------------------------------------

func (s *Service) getAccount(ctx context.Context, id uuid.UUID) (CloudAccount, error) {
	var (
		acct       CloudAccount
		roleARN    *string
		regionsRaw []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, provider, account_label, external_id,
		       credential_ref, role_arn, regions
		  FROM cloud_accounts WHERE id = $1`, id).
		Scan(&acct.ID, &acct.TenantID, &acct.Provider, &acct.AccountLabel,
			&acct.ExternalID, &acct.CredentialRef, &roleARN, &regionsRaw)
	if err != nil {
		return acct, err
	}
	if roleARN != nil {
		acct.RoleARN = *roleARN
	}
	_ = json.Unmarshal(regionsRaw, &acct.Regions)
	return acct, nil
}

func (s *Service) computeDrift(ctx context.Context, accountID uuid.UUID, current []ControlResult) error {
	// Pull the previous snapshot (second-most-recent — the most recent
	// IS the one we just wrote).
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT findings FROM cloud_posture_snapshots
		 WHERE account_id = $1
		 ORDER BY snapshot_at DESC OFFSET 1 LIMIT 1`, accountID).Scan(&raw)
	if err != nil {
		// No prior snapshot — nothing to compare. Not an error.
		return nil
	}
	var prev []ControlResult
	if err := json.Unmarshal(raw, &prev); err != nil {
		return err
	}
	prevByID := map[string]string{}
	for _, r := range prev {
		prevByID[r.ControlID] = r.Status
	}
	for _, r := range current {
		previous, existed := prevByID[r.ControlID]
		if !existed || previous == r.Status {
			continue
		}
		direction := "improved"
		if statusRank(previous) > statusRank(r.Status) {
			direction = "regressed"
		}
		if _, err := s.pool.Exec(ctx, `
			INSERT INTO cloud_drift_events(account_id, control_id, direction,
			    previous_state, current_state)
			VALUES ($1, $2, $3, $4, $5)`,
			accountID, r.ControlID, direction, previous, r.Status); err != nil {
			return err
		}
	}
	return nil
}

func score(results []ControlResult) float64 {
	s := scoreBreakdown(results)
	return s.Score
}

// ScoreBreakdown carries both the pass-rate and the automation
// coverage so dashboards can show "80% pass / 60% coverage" rather
// than just the headline percentage. A 100% pass over a 30%
// automated control set is a very different posture than 100% over
// 95% automated, and customers deserve to see both.
type ScoreBreakdown struct {
	Score             float64 `json:"score"`                  // pass / (pass+fail) × 100
	AutomatedCount    int     `json:"automated_count"`        // pass+fail
	ManualCount       int     `json:"manual_count"`           // status=manual
	NotApplicable     int     `json:"not_applicable_count"`   // status=not_applicable
	TotalCount        int     `json:"total_count"`
	CoveragePercent   float64 `json:"coverage_percent"`       // automated / (automated+manual) × 100
}

// scoreBreakdown returns the headline score and the automation
// coverage. Manual / not_applicable are still excluded from the
// pass-rate denominator (counting them as fail would punish
// accounts for our automation gaps), but the breakdown exposes
// them so the customer sees the full picture.
func scoreBreakdown(results []ControlResult) ScoreBreakdown {
	b := ScoreBreakdown{TotalCount: len(results)}
	if len(results) == 0 {
		return b
	}
	var pass, fail float64
	for _, r := range results {
		switch r.Status {
		case "pass":
			pass++
		case "fail":
			fail++
		case "manual":
			b.ManualCount++
		case "not_applicable":
			b.NotApplicable++
		}
	}
	b.AutomatedCount = int(pass + fail)
	if b.AutomatedCount > 0 {
		b.Score = pass / (pass + fail) * 100
	}
	denom := b.AutomatedCount + b.ManualCount
	if denom > 0 {
		b.CoveragePercent = float64(b.AutomatedCount) / float64(denom) * 100
	}
	return b
}

func statusRank(s string) int {
	switch strings.ToLower(s) {
	case "pass":
		return 3
	case "manual":
		return 2
	case "fail":
		return 1
	}
	return 0
}

// ----- A dev/test adapter that the harness uses ----------------------------

// StaticAdapter satisfies ProviderAdapter with a fixed set of results.
// Used by integration tests + early dev when the real cloud SDKs
// aren't wired yet.
type StaticAdapter struct {
	provider string
	Results  []ControlResult
}

func NewStaticAdapter(provider string, results []ControlResult) *StaticAdapter {
	return &StaticAdapter{provider: provider, Results: results}
}

func (a *StaticAdapter) Provider() string { return a.provider }
func (a *StaticAdapter) Scan(_ context.Context, _ CloudAccount) ([]ControlResult, error) {
	return a.Results, nil
}
