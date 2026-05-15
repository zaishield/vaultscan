package assets

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/models"
)

// IngestSubfinder parses a subfinder JSONL stream and writes one asset row
// per discovered host. Subfinder emits one JSON document per line:
//   {"host":"api.example.com","input":"example.com","source":"crtsh"}
// Idempotent via the existing UNIQUE(tenant_id, asset_type, value) +
// fuzzy dedup_key index (migration 0020).
//
// Returns (created, skippedExisting).
func (s *Service) IngestSubfinder(ctx context.Context, ctxIn IngestContext, body io.Reader) (int, int, error) {
	if ctxIn.TenantID == uuid.Nil || ctxIn.PartnerID == uuid.Nil {
		return 0, 0, errors.New("assets: tenant + partner required")
	}
	created, skipped := 0, 0
	br := bufio.NewReader(body)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			var doc struct{ Host, Source string }
			if err := json.Unmarshal(bytesNoNewline(line), &doc); err == nil && doc.Host != "" {
				if isNew, e := s.ingestDiscoveredHost(ctx, ctxIn, doc.Host, "subfinder", doc.Source); e == nil {
					if isNew {
						created++
					} else {
						skipped++
					}
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return created, skipped, err
		}
	}
	return created, skipped, nil
}

// IngestAmass parses Amass's JSON output (one object per line). Format:
//   {"name":"api.example.com","domain":"example.com","sources":["crtsh","cert"]}
func (s *Service) IngestAmass(ctx context.Context, ctxIn IngestContext, body io.Reader) (int, int, error) {
	created, skipped := 0, 0
	br := bufio.NewReader(body)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			var doc struct {
				Name    string
				Sources []string
			}
			if err := json.Unmarshal(bytesNoNewline(line), &doc); err == nil && doc.Name != "" {
				src := strings.Join(doc.Sources, ",")
				if isNew, e := s.ingestDiscoveredHost(ctx, ctxIn, doc.Name, "amass", src); e == nil {
					if isNew {
						created++
					} else {
						skipped++
					}
				}
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return created, skipped, err
		}
	}
	return created, skipped, nil
}

// IngestContext supplies the tenant + partner + (optional) parent context.
// A typical caller is the scanner worker handing off external-discovery
// output for a specific scan_job_id.
type IngestContext struct {
	PlatformID   uuid.UUID
	PartnerID    uuid.UUID
	TenantID     uuid.UUID
	EngagementID *uuid.UUID
	ParentAssetID *uuid.UUID // root domain when ingesting subdomains
	ScanJobID    *uuid.UUID
	Actor        *uuid.UUID
}

// ingestDiscoveredHost upserts one asset and (if ParentAssetID is set)
// records a 'contains' relationship + a discovery_history row.
func (s *Service) ingestDiscoveredHost(ctx context.Context, in IngestContext, host, tool, source string) (bool, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false, nil
	}
	assetType := "subdomain"
	if !strings.Contains(host, ".") {
		assetType = "domain"
	}
	a, err := s.Create(ctx, CreateInput{
		PlatformID: in.PlatformID, PartnerID: in.PartnerID,
		TenantID: in.TenantID, EngagementID: in.EngagementID,
		AssetType: assetType, Value: host, Name: host,
		Plane: "external", Criticality: "unknown",
		DiscoveredVia: "external_discovery",
		CreatedBy:     in.Actor,
	})
	if err != nil {
		return false, fmt.Errorf("assets: ingest %s: %w", host, err)
	}
	// Was this row brand new, or did Create.touchExisting fire? Compare
	// first_seen against now (within 1 second is "new").
	isNew := a.FirstSeen.Equal(a.LastSeen)

	// History row links the discovery back to the scan job + tool.
	historyJSON, _ := json.Marshal(map[string]any{"source": source})
	_, _ = s.pool.Exec(ctx, `
		INSERT INTO asset_discovery_history(asset_id, source, payload, scan_job_id, tool)
		VALUES ($1, $2, $3::jsonb, $4, $5)`,
		a.ID, source, historyJSON, in.ScanJobID, tool)

	if in.ParentAssetID != nil && *in.ParentAssetID != a.ID {
		_, _ = s.pool.Exec(ctx, `
			INSERT INTO asset_relationships(parent_id, child_id, kind)
			VALUES ($1, $2, 'contains')
			ON CONFLICT DO NOTHING`, *in.ParentAssetID, a.ID)
	}
	return isNew, nil
}

// ----- Relationship graph queries -----------------------------------------

type RelatedAsset struct {
	ID         uuid.UUID `json:"id"`
	AssetType  string    `json:"asset_type"`
	Value      string    `json:"value"`
	Kind       string    `json:"relationship"`
}

// Children returns assets that this asset 'contains' or 'owns'.
func (s *Service) Children(ctx context.Context, parentID uuid.UUID) ([]RelatedAsset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.asset_type, a.value, r.kind
		  FROM asset_relationships r
		  JOIN assets a ON a.id = r.child_id
		 WHERE r.parent_id = $1
		 ORDER BY r.kind, a.value`, parentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RelatedAsset{}
	for rows.Next() {
		var r RelatedAsset
		if err := rows.Scan(&r.ID, &r.AssetType, &r.Value, &r.Kind); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Parents returns assets that contain or own this one.
func (s *Service) Parents(ctx context.Context, childID uuid.UUID) ([]RelatedAsset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.asset_type, a.value, r.kind
		  FROM asset_relationships r
		  JOIN assets a ON a.id = r.parent_id
		 WHERE r.child_id = $1`, childID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RelatedAsset{}
	for rows.Next() {
		var r RelatedAsset
		if err := rows.Scan(&r.ID, &r.AssetType, &r.Value, &r.Kind); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// LinkAssets records a relationship between two assets.
func (s *Service) LinkAssets(ctx context.Context, actor *uuid.UUID, parentID, childID uuid.UUID, kind string) error {
	if parentID == childID {
		return errors.New("assets: cannot link an asset to itself")
	}
	allowed := map[string]bool{"contains": true, "depends_on": true, "owns": true, "hosts": true}
	if !allowed[kind] {
		return fmt.Errorf("assets: relationship kind %q not allowed", kind)
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO asset_relationships(parent_id, child_id, kind)
		VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		parentID, childID, kind); err != nil {
		return err
	}
	var tenantID, platformID, partnerID uuid.UUID
	_ = s.pool.QueryRow(ctx,
		`SELECT tenant_id, platform_id, partner_id FROM assets WHERE id=$1`, parentID).
		Scan(&tenantID, &platformID, &partnerID)
	return s.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &partnerID, TenantID: &tenantID, ActorID: actor,
		Event: "asset.relationship_added", TargetType: "asset", TargetID: parentID.String(),
		Payload: map[string]any{"child_id": childID, "kind": kind},
	})
}

// FuzzyDedupHit reports any other asset of the same type whose dedup_key
// (lowercased, www-stripped) collides with the candidate value. Helps the
// import UI warn about likely duplicates BEFORE the unique constraint
// rejects them.
type FuzzyDedupHit struct {
	ID       uuid.UUID `json:"id"`
	Value    string    `json:"value"`
	DedupKey string    `json:"dedup_key"`
}

func (s *Service) FuzzyDedupCandidates(ctx context.Context, tenantID uuid.UUID, assetType, value string) ([]FuzzyDedupHit, error) {
	key := strings.TrimPrefix(strings.ToLower(value), "www.")
	rows, err := s.pool.Query(ctx, `
		SELECT id, value, COALESCE(dedup_key, '')
		  FROM assets
		 WHERE tenant_id = $1
		   AND asset_type = $2
		   AND dedup_key = $3`, tenantID, assetType, key)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FuzzyDedupHit
	for rows.Next() {
		var h FuzzyDedupHit
		if err := rows.Scan(&h.ID, &h.Value, &h.DedupKey); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

var _ = models.Asset{} // referenced via the existing Service.Create call signature.

func bytesNoNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
