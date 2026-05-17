// handlers_isolation.go — tenant isolation-mode promotion.
//
// Promotion from "shared" to "dedicated" is one-way (the reverse is
// a runbook operation, not a clickable button). create_tenant
// permission floor; audited via tenant_isolation_history.
package api

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/auth"
)

type promoteIsolationReq struct {
	Reason string `json:"reason"`
}

func promoteTenantIsolation(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, "invalid tenant_id")
			return
		}
		var req promoteIsolationReq
		_ = decode(r, &req) // reason optional; empty is fine
		var actor *uuid.UUID
		if id, ierr := auth.FromContext(r.Context()); ierr == nil && id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Tenants.PromoteToDedicated(r.Context(), tenantID, actor, req.Reason); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status":         "ok",
			"isolation_mode": "dedicated",
			"next_steps":     "operator must follow runbook to populate tenant_pool_routing and dedicated_kek_ref; until then, dedicated tenant degrades to shared isolation",
		})
	}
}
