// Package assets implements asset inventory CRUD and bulk import (Blueprint §16).
package assets

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

type Service struct {
	pool      *pgxpool.Pool
	audit     *audit.Service
	billing   AssetQuotaChecker
	residency ResidencyChecker
	podRegion string
}

// AssetQuotaChecker is the slice of billing.Service the assets
// package actually calls. Defined as an interface so assets doesn't
// import billing directly (clean unit-testability + the import
// graph stays flat).
type AssetQuotaChecker interface {
	CheckAsset(ctx context.Context, partnerID uuid.UUID, actor *uuid.UUID) error
}

// ResidencyChecker mirrors scanorch.ResidencyChecker — the slice of
// tenants.Service required for the residency gate.
type ResidencyChecker interface {
	CheckResidency(ctx context.Context, tenantID uuid.UUID, podRegion string) error
}

func New(pool *pgxpool.Pool, a *audit.Service) *Service {
	return &Service{pool: pool, audit: a}
}

// WithBilling attaches the partner-level asset-quota gate. Create()
// calls CheckAsset before INSERT; ErrQuotaExceeded propagates so the
// API can return a 429.
func (s *Service) WithBilling(b AssetQuotaChecker) *Service {
	s.billing = b
	return s
}

// WithResidency attaches the data-residency gate. Create() refuses
// inserts when the tenant is pinned to a region different from the
// pod's VAULTSCAN_REGION. Empty podRegion disables the check.
func (s *Service) WithResidency(r ResidencyChecker, podRegion string) *Service {
	s.residency = r
	s.podRegion = podRegion
	return s
}

type CreateInput struct {
	PlatformID    uuid.UUID
	PartnerID     uuid.UUID
	TenantID      uuid.UUID
	EngagementID  *uuid.UUID
	AssetType     string
	Name          string
	Value         string
	Plane         string
	Criticality   string
	Owner         string
	Environment   string
	CloudProvider string
	Tags          []string
	Metadata      map[string]any
	DiscoveredVia string
	CreatedBy     *uuid.UUID
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*models.Asset, error) {
	if in.AssetType == "" || in.Value == "" {
		return nil, errors.New("assets: type and value required")
	}
	if !validType(in.AssetType) {
		return nil, fmt.Errorf("assets: unsupported asset_type %q", in.AssetType)
	}
	if in.Criticality == "" {
		in.Criticality = "unknown"
	}
	if in.Plane == "" {
		in.Plane = "external"
	}
	if in.DiscoveredVia == "" {
		in.DiscoveredVia = "manual"
	}
	if in.Name == "" {
		in.Name = in.Value
	}
	// Data-residency gate. Runs first — a residency violation is
	// terminal; everything downstream is wasted work.
	if s.residency != nil && s.podRegion != "" {
		if err := s.residency.CheckResidency(ctx, in.TenantID, s.podRegion); err != nil {
			return nil, err
		}
	}
	// Partner asset-quota gate. Returns ErrQuotaExceeded if the
	// partner's billing plan caps assets and they're at the limit.
	// nil billing service = no enforcement (legacy dev path).
	if s.billing != nil {
		if err := s.billing.CheckAsset(ctx, in.PartnerID, in.CreatedBy); err != nil {
			return nil, err
		}
	}
	tagsJSON, _ := json.Marshal(in.Tags)
	metaJSON, _ := json.Marshal(in.Metadata)
	a := &models.Asset{
		ID: uuid.New(), PlatformID: in.PlatformID, PartnerID: in.PartnerID,
		TenantID: in.TenantID, EngagementID: in.EngagementID,
		AssetType: in.AssetType, Name: in.Name, Value: in.Value,
		Plane: in.Plane, Criticality: in.Criticality, Owner: in.Owner,
		Environment: in.Environment, CloudProvider: in.CloudProvider,
		Tags: in.Tags, Metadata: in.Metadata, DiscoveredVia: in.DiscoveredVia,
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO assets(id, platform_id, partner_id, tenant_id, engagement_id,
		    asset_type, name, value, plane, criticality, owner, environment, cloud_provider,
		    tags, metadata, discovered_via, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		RETURNING first_seen, last_seen, created_at`,
		a.ID, a.PlatformID, a.PartnerID, a.TenantID, a.EngagementID,
		a.AssetType, a.Name, a.Value, a.Plane, a.Criticality,
		nullIfEmpty(a.Owner), nullIfEmpty(a.Environment), nullIfEmpty(a.CloudProvider),
		tagsJSON, metaJSON, a.DiscoveredVia, in.CreatedBy,
	).Scan(&a.FirstSeen, &a.LastSeen, &a.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		// Idempotent upsert: bump last_seen, return existing.
		return s.touchExisting(ctx, in.TenantID, in.AssetType, in.Value)
	}
	if err != nil {
		return nil, fmt.Errorf("assets: insert: %w", err)
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: a.PlatformID, PartnerID: &a.PartnerID, TenantID: &a.TenantID,
		ActorID: in.CreatedBy, Event: "asset.created",
		TargetType: "asset", TargetID: a.ID.String(),
		Payload: map[string]any{"type": a.AssetType, "value": a.Value},
	})
	return a, nil
}

func (s *Service) touchExisting(ctx context.Context, tenant uuid.UUID, t, v string) (*models.Asset, error) {
	a := &models.Asset{}
	var tagsJSON, metaJSON []byte
	var owner, env, cloud *string
	err := s.pool.QueryRow(ctx, `
		UPDATE assets SET last_seen=now()
		 WHERE tenant_id=$1 AND asset_type=$2 AND value=$3
		 RETURNING id, platform_id, partner_id, tenant_id, engagement_id, asset_type,
		           name, value, plane, criticality, owner, environment, cloud_provider,
		           tags, metadata, discovered_via, first_seen, last_seen, created_at`,
		tenant, t, v).
		Scan(&a.ID, &a.PlatformID, &a.PartnerID, &a.TenantID, &a.EngagementID,
			&a.AssetType, &a.Name, &a.Value, &a.Plane, &a.Criticality,
			&owner, &env, &cloud, &tagsJSON, &metaJSON, &a.DiscoveredVia,
			&a.FirstSeen, &a.LastSeen, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	if owner != nil {
		a.Owner = *owner
	}
	if env != nil {
		a.Environment = *env
	}
	if cloud != nil {
		a.CloudProvider = *cloud
	}
	_ = json.Unmarshal(tagsJSON, &a.Tags)
	_ = json.Unmarshal(metaJSON, &a.Metadata)
	return a, nil
}

type ListFilter struct {
	TenantID     uuid.UUID
	EngagementID *uuid.UUID
	AssetType    string
	Plane        string
	Criticality  string
	Search       string
	Limit, Offset int
}

func (s *Service) List(ctx context.Context, f ListFilter) ([]models.Asset, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	// See findings.Service.List for the OFFSET-bound rationale: deep
	// offsets force PG to walk past every preceding row, turning a
	// /list request into an O(N) table scan. Cap at 100k.
	if f.Offset < 0 {
		f.Offset = 0
	}
	if f.Offset > 100_000 {
		f.Offset = 100_000
	}
	args := []any{f.TenantID}
	q := `SELECT id, platform_id, partner_id, tenant_id, engagement_id, asset_type,
	             name, value, plane, criticality, COALESCE(owner,''), COALESCE(environment,''),
	             COALESCE(cloud_provider,''), tags, metadata, discovered_via,
	             first_seen, last_seen, created_at
	        FROM assets
	       WHERE tenant_id=$1`
	if f.EngagementID != nil {
		q += fmt.Sprintf(" AND engagement_id=$%d", len(args)+1)
		args = append(args, *f.EngagementID)
	}
	if f.AssetType != "" {
		q += fmt.Sprintf(" AND asset_type=$%d", len(args)+1)
		args = append(args, f.AssetType)
	}
	if f.Plane != "" {
		q += fmt.Sprintf(" AND plane=$%d", len(args)+1)
		args = append(args, f.Plane)
	}
	if f.Criticality != "" {
		q += fmt.Sprintf(" AND criticality=$%d", len(args)+1)
		args = append(args, f.Criticality)
	}
	if f.Search != "" {
		q += fmt.Sprintf(" AND (value ILIKE $%d OR name ILIKE $%d)", len(args)+1, len(args)+1)
		args = append(args, "%"+f.Search+"%")
	}
	q += fmt.Sprintf(" ORDER BY last_seen DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []models.Asset{}
	for rows.Next() {
		var a models.Asset
		var tagsJSON, metaJSON []byte
		if err := rows.Scan(&a.ID, &a.PlatformID, &a.PartnerID, &a.TenantID, &a.EngagementID,
			&a.AssetType, &a.Name, &a.Value, &a.Plane, &a.Criticality,
			&a.Owner, &a.Environment, &a.CloudProvider, &tagsJSON, &metaJSON,
			&a.DiscoveredVia, &a.FirstSeen, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(tagsJSON, &a.Tags)
		_ = json.Unmarshal(metaJSON, &a.Metadata)
		out = append(out, a)
	}
	return out, rows.Err()
}

// ImportCSV reads a CSV with headers asset_type,value,name,plane,criticality
// and creates / refreshes assets for the tenant.
func (s *Service) ImportCSV(ctx context.Context, in CreateInput, body io.Reader) (created, updated int, err error) {
	r := csv.NewReader(body)
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if err != nil {
		return 0, 0, fmt.Errorf("assets: csv header: %w", err)
	}
	idx := map[string]int{}
	for i, h := range header {
		idx[strings.ToLower(strings.TrimSpace(h))] = i
	}
	required := []string{"asset_type", "value"}
	for _, k := range required {
		if _, ok := idx[k]; !ok {
			return 0, 0, fmt.Errorf("assets: csv missing column %q", k)
		}
	}
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return created, updated, err
		}
		ci := in
		ci.AssetType = row[idx["asset_type"]]
		ci.Value = row[idx["value"]]
		if i, ok := idx["name"]; ok {
			ci.Name = row[i]
		}
		if i, ok := idx["plane"]; ok {
			ci.Plane = row[i]
		}
		if i, ok := idx["criticality"]; ok {
			ci.Criticality = row[i]
		}
		if i, ok := idx["owner"]; ok {
			ci.Owner = row[i]
		}
		if i, ok := idx["environment"]; ok {
			ci.Environment = row[i]
		}
		ci.DiscoveredVia = "csv"
		_, err = s.Create(ctx, ci)
		if err != nil {
			return created, updated, err
		}
		created++
	}
	return created, 0, nil
}

// BulkOp is one of the bulk mutations the API exposes on assets.
type BulkOp struct {
	IDs         []uuid.UUID
	Action      string         // delete | retag | reassign | recriticality
	Tags        []string       // for retag
	Engagement  *uuid.UUID     // for reassign
	Criticality string         // for recriticality
	Actor       *uuid.UUID
}

// Bulk applies an operation to the given asset IDs in one transaction.
// Returns the number of rows affected.
func (s *Service) Bulk(ctx context.Context, tenantID uuid.UUID, op BulkOp) (int, error) {
	if len(op.IDs) == 0 {
		return 0, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var n int64
	switch op.Action {
	case "delete":
		tag, err := tx.Exec(ctx,
			`DELETE FROM assets WHERE tenant_id=$1 AND id = ANY($2)`,
			tenantID, op.IDs)
		if err != nil {
			return 0, err
		}
		n = tag.RowsAffected()
	case "retag":
		tagsJSON, _ := json.Marshal(op.Tags)
		tag, err := tx.Exec(ctx, `
			UPDATE assets SET tags=$3::jsonb, updated_at=now()
			 WHERE tenant_id=$1 AND id = ANY($2)`,
			tenantID, op.IDs, tagsJSON)
		if err != nil {
			return 0, err
		}
		n = tag.RowsAffected()
	case "reassign":
		if op.Engagement == nil {
			return 0, errors.New("assets: bulk reassign requires engagement_id")
		}
		tag, err := tx.Exec(ctx, `
			UPDATE assets SET engagement_id=$3, updated_at=now()
			 WHERE tenant_id=$1 AND id = ANY($2)`,
			tenantID, op.IDs, *op.Engagement)
		if err != nil {
			return 0, err
		}
		n = tag.RowsAffected()
	case "recriticality":
		valid := false
		for _, c := range models.CriticalityLevels {
			if c == op.Criticality {
				valid = true
				break
			}
		}
		if !valid {
			return 0, fmt.Errorf("assets: criticality %q not in allowed set", op.Criticality)
		}
		tag, err := tx.Exec(ctx, `
			UPDATE assets SET criticality=$3, updated_at=now()
			 WHERE tenant_id=$1 AND id = ANY($2)`,
			tenantID, op.IDs, op.Criticality)
		if err != nil {
			return 0, err
		}
		n = tag.RowsAffected()
	default:
		return 0, fmt.Errorf("assets: unknown bulk action %q", op.Action)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: tenantID, TenantID: &tenantID, ActorID: op.Actor,
		Event: "asset.bulk_" + op.Action, TargetType: "asset",
		Payload: map[string]any{"count": n, "ids": len(op.IDs)},
	})
	return int(n), nil
}

// RecomputeRiskScore updates the asset's composite risk score. Formula:
//   open-critical*10 + open-high*5 + open-medium*2 + open-low*1,
// then weighted by asset criticality (critical=1.5, high=1.2, medium=1.0,
// low=0.7, unknown=0.8). Capped at 100. Called on every finding ingest +
// finding state transition.
func (s *Service) RecomputeRiskScore(ctx context.Context, assetID uuid.UUID) error {
	var counts struct {
		critical, high, medium, low int
		criticality                 string
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE severity='critical' AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  COUNT(*) FILTER (WHERE severity='high'     AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  COUNT(*) FILTER (WHERE severity='medium'   AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  COUNT(*) FILTER (WHERE severity='low'      AND status NOT IN ('closed','remediated','retest_passed','false_positive')),
		  COALESCE((SELECT criticality FROM assets WHERE id = $1), 'unknown')
		  FROM findings WHERE asset_id = $1`, assetID).
		Scan(&counts.critical, &counts.high, &counts.medium, &counts.low, &counts.criticality); err != nil {
		return err
	}
	raw := float64(counts.critical*10 + counts.high*5 + counts.medium*2 + counts.low)
	weight := map[string]float64{
		"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.7, "unknown": 0.8,
	}[counts.criticality]
	if weight == 0 {
		weight = 1.0
	}
	score := raw * weight
	if score > 100 {
		score = 100
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE assets SET risk_score=$2, updated_at=now() WHERE id=$1`,
		assetID, score)
	return err
}

func validType(t string) bool {
	for _, v := range models.AssetTypes {
		if v == t {
			return true
		}
	}
	return false
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// rowsTime is a helper kept for compatibility.
var _ = pgx.ErrNoRows
var _ = time.Time{}
