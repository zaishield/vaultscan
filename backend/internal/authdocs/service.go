// Package authdocs handles signed authorization document upload, encryption,
// and linkage to engagements (Blueprint §14.5, §24.2).
package authdocs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
)

type Service struct {
	pool       *pgxpool.Pool
	store      *evidence.Vault
	audit      *audit.Service
	bus        *eventbus.Bus
}

func New(pool *pgxpool.Pool, store *evidence.Vault, a *audit.Service, b *eventbus.Bus) *Service {
	return &Service{pool: pool, store: store, audit: a, bus: b}
}

type UploadInput struct {
	EngagementID uuid.UUID
	Title        string
	DocumentType string
	Body         io.Reader
	ContentType  string
	SignedBy     string
	SignedAt     *time.Time
}

func (s *Service) Upload(ctx context.Context, actor *uuid.UUID, in UploadInput) (uuid.UUID, error) {
	body, err := io.ReadAll(in.Body)
	if err != nil {
		return uuid.Nil, fmt.Errorf("authdocs: read: %w", err)
	}
	digest := sha256.Sum256(body)
	hashHex := hex.EncodeToString(digest[:])

	// Resolve engagement context for storage path / audit
	var platformID, partnerID, tenantID uuid.UUID
	if err := s.pool.QueryRow(ctx,
		`SELECT platform_id, partner_id, tenant_id FROM engagements WHERE id=$1`, in.EngagementID).
		Scan(&platformID, &partnerID, &tenantID); err != nil {
		return uuid.Nil, fmt.Errorf("authdocs: engagement: %w", err)
	}

	storageURL, err := s.store.Put(ctx, evidence.PutInput{
		TenantID:    tenantID,
		Kind:        "authorization",
		ContentType: in.ContentType,
		Body:        body,
	})
	if err != nil {
		return uuid.Nil, err
	}

	id := uuid.New()
	_, err = s.pool.Exec(ctx, `
		INSERT INTO authorization_documents(id, engagement_id, title, document_type,
		    storage_url, sha256, signed_by, signed_at, uploaded_by, encrypted)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true)`,
		id, in.EngagementID, in.Title, in.DocumentType, storageURL, hashHex,
		in.SignedBy, in.SignedAt, actor)
	if err != nil {
		return uuid.Nil, fmt.Errorf("authdocs: insert: %w", err)
	}

	_ = s.audit.Record(ctx, audit.Entry{
		PlatformID: platformID, PartnerID: &partnerID, TenantID: &tenantID,
		ActorID: actor, Event: audit.EventAuthorizationUploaded,
		TargetType: "authorization_document", TargetID: id.String(),
		Payload: map[string]any{
			"engagement_id": in.EngagementID, "title": in.Title,
			"document_type": in.DocumentType, "sha256": hashHex,
		},
	})
	_ = s.bus.Publish(ctx, eventbus.Event{
		Type: eventbus.AuthorizationUploaded, TenantID: &tenantID, PartnerID: &partnerID,
		ActorID: actor, Payload: map[string]any{"engagement_id": in.EngagementID, "doc_id": id},
	})
	return id, nil
}
