// §34 Partner integration marketplace endpoints.
//
// Flow:
//   1. GET /api/v1/marketplace/listings           — browse the catalog
//   2. POST /api/v1/marketplace/installs          — install a listing
//      (state=pending_config; integrations row created with disabled=true)
//   3. PATCH /api/v1/marketplace/installs/{id}    — provide config
//      → integrations.config + .enabled=true, state=active
//   4. DELETE /api/v1/marketplace/installs/{id}   — uninstall
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

func listMarketplaceListings(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		category := r.URL.Query().Get("category")
		q := `SELECT id, slug, name, publisher, category, description,
		             integration_type, config_schema, COALESCE(docs_url,''),
		             COALESCE(logo_url,''), verified
		        FROM marketplace_listings
		       WHERE enabled = true`
		args := []any{}
		if category != "" {
			q += " AND category = $1"
			args = append(args, category)
		}
		q += " ORDER BY verified DESC, name"
		rows, err := s.Pool.Query(r.Context(), q, args...)
		if err != nil {
			internalErr(w, err)
			return
		}
		defer rows.Close()
		type listing struct {
			ID              uuid.UUID       `json:"id"`
			Slug            string          `json:"slug"`
			Name            string          `json:"name"`
			Publisher       string          `json:"publisher"`
			Category        string          `json:"category"`
			Description     string          `json:"description"`
			IntegrationType string          `json:"integration_type"`
			ConfigSchema    json.RawMessage `json:"config_schema"`
			DocsURL         string          `json:"docs_url,omitempty"`
			LogoURL         string          `json:"logo_url,omitempty"`
			Verified        bool            `json:"verified"`
		}
		var out []listing
		for rows.Next() {
			var l listing
			var schemaRaw []byte
			if err := rows.Scan(&l.ID, &l.Slug, &l.Name, &l.Publisher,
				&l.Category, &l.Description, &l.IntegrationType, &schemaRaw,
				&l.DocsURL, &l.LogoURL, &l.Verified); err != nil {
				continue
			}
			l.ConfigSchema = schemaRaw
			out = append(out, l)
		}
		writeJSON(w, http.StatusOK, map[string]any{"listings": out})
	}
}

func installFromMarketplace(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		if id.TenantID == nil {
			badRequest(w, "tenant context required")
			return
		}
		var req struct {
			ListingID  uuid.UUID      `json:"listing_id"`
			ListingSlug string        `json:"listing_slug"`
			Label      string         `json:"label"`
			Config     map[string]any `json:"config"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		// Resolve listing by id or slug.
		var (
			listingID       uuid.UUID
			integrationType string
		)
		switch {
		case req.ListingID != uuid.Nil:
			err = s.Pool.QueryRow(r.Context(),
				`SELECT id, integration_type FROM marketplace_listings
				 WHERE id=$1 AND enabled=true`, req.ListingID).
				Scan(&listingID, &integrationType)
		case req.ListingSlug != "":
			err = s.Pool.QueryRow(r.Context(),
				`SELECT id, integration_type FROM marketplace_listings
				 WHERE slug=$1 AND enabled=true`, req.ListingSlug).
				Scan(&listingID, &integrationType)
		default:
			badRequest(w, "listing_id or listing_slug required")
			return
		}
		if err != nil {
			notFound(w)
			return
		}
		// Create the underlying integrations row (disabled until config arrives).
		cfgJSON, _ := json.Marshal(req.Config)
		var integID uuid.UUID
		label := req.Label
		if label == "" {
			label = "marketplace-install"
		}
		err = s.Pool.QueryRow(r.Context(), `
			INSERT INTO integrations(tenant_id, type, name, enabled, config, created_by)
			VALUES ($1, $2, $3, $4, $5::jsonb, $6) RETURNING id`,
			id.TenantID, integrationType, label, len(req.Config) > 0,
			cfgJSON, id.UserID).Scan(&integID)
		if err != nil {
			internalErr(w, err)
			return
		}
		// Bind the install row.
		state := "pending_config"
		if len(req.Config) > 0 {
			state = "active"
		}
		var installID uuid.UUID
		err = s.Pool.QueryRow(r.Context(), `
			INSERT INTO marketplace_installs(listing_id, tenant_id, integration_id,
			    install_state, installed_by)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, listing_id) DO UPDATE
			   SET integration_id = EXCLUDED.integration_id,
			       install_state  = EXCLUDED.install_state,
			       installed_at   = now(),
			       suspended_at   = NULL
			RETURNING id`,
			listingID, id.TenantID, integID, state, id.UserID).Scan(&installID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"install_id":     installID,
			"integration_id": integID,
			"state":          state,
		})
	}
}

func configureMarketplaceInstall(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installID, err := uuidParam(r, "install_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil || id.TenantID == nil {
			badRequest(w, "tenant context required")
			return
		}
		var req struct {
			Config map[string]any `json:"config"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		cfgJSON, _ := json.Marshal(req.Config)
		// Update integrations row + flip install to active. Use a
		// transaction so we don't end up with an active install
		// pointing at a still-disabled integration.
		tx, err := s.Pool.Begin(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		defer tx.Rollback(r.Context())
		var integID uuid.UUID
		err = tx.QueryRow(r.Context(), `
			SELECT integration_id FROM marketplace_installs
			 WHERE id = $1 AND tenant_id = $2`,
			installID, id.TenantID).Scan(&integID)
		if err != nil {
			notFound(w)
			return
		}
		if _, err := tx.Exec(r.Context(), `
			UPDATE integrations SET config = $2::jsonb, enabled = true
			 WHERE id = $1`, integID, cfgJSON); err != nil {
			internalErr(w, err)
			return
		}
		if _, err := tx.Exec(r.Context(), `
			UPDATE marketplace_installs
			   SET install_state = 'active',
			       suspended_at = NULL,
			       last_used_at = now()
			 WHERE id = $1`, installID); err != nil {
			internalErr(w, err)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"state": "active"})
	}
}

func uninstallMarketplaceInstall(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		installID, err := uuidParam(r, "install_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id == nil || id.TenantID == nil {
			badRequest(w, "tenant context required")
			return
		}
		// Soft-delete: integration disabled, install row marked
		// suspended. Keeps the audit trail intact.
		tx, err := s.Pool.Begin(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		defer tx.Rollback(r.Context())
		var integID *uuid.UUID
		err = tx.QueryRow(r.Context(), `
			SELECT integration_id FROM marketplace_installs
			 WHERE id = $1 AND tenant_id = $2`,
			installID, id.TenantID).Scan(&integID)
		if err != nil {
			notFound(w)
			return
		}
		if integID != nil {
			if _, err := tx.Exec(r.Context(),
				`UPDATE integrations SET enabled = false WHERE id = $1`,
				*integID); err != nil {
				internalErr(w, err)
				return
			}
		}
		if _, err := tx.Exec(r.Context(), `
			UPDATE marketplace_installs
			   SET install_state = 'suspended',
			       suspended_at = now(),
			       suspension_reason = 'uninstalled by user'
			 WHERE id = $1`, installID); err != nil {
			internalErr(w, err)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"state": "suspended"})
	}
}

func listMarketplaceInstalls(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil || id.TenantID == nil {
			badRequest(w, "tenant context required")
			return
		}
		rows, err := s.Pool.Query(r.Context(), `
			SELECT i.id, l.name, l.slug, l.category, l.integration_type,
			       i.install_state, i.installed_at, i.integration_id
			  FROM marketplace_installs i
			  JOIN marketplace_listings l ON l.id = i.listing_id
			 WHERE i.tenant_id = $1
			 ORDER BY i.installed_at DESC`, id.TenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		defer rows.Close()
		type install struct {
			ID              uuid.UUID  `json:"id"`
			Name            string     `json:"listing_name"`
			Slug            string     `json:"listing_slug"`
			Category        string     `json:"category"`
			IntegrationType string     `json:"integration_type"`
			State           string     `json:"state"`
			InstalledAt     string     `json:"installed_at"`
			IntegrationID   *uuid.UUID `json:"integration_id,omitempty"`
		}
		var out []install
		for rows.Next() {
			var inst install
			var installedAt time.Time
			if err := rows.Scan(&inst.ID, &inst.Name, &inst.Slug, &inst.Category,
				&inst.IntegrationType, &inst.State, &installedAt,
				&inst.IntegrationID); err != nil {
				continue
			}
			inst.InstalledAt = installedAt.UTC().Format(time.RFC3339)
			out = append(out, inst)
		}
		writeJSON(w, http.StatusOK, map[string]any{"installs": out})
	}
}
