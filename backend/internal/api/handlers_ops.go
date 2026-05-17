// HTTP handlers for the deepened VS-05..VS-12 + HS-01/02/05 surfaces.
// One file keeps the wiring grep-able from `server.go`.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/auth"
	"github.com/zaishield/vaultscan/backend/internal/dashboards"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/retesting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

// ============================================================================
// VS-05 Scanner ops
// ============================================================================

func recordScannerHeartbeat(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodeID, err := uuidParam(r, "node_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var hb scanorch.Heartbeat
		if err := decode(r, &hb); err != nil {
			badRequest(w, err.Error())
			return
		}
		hb.NodeID = nodeID
		if s.Nodes == nil {
			internalErr(w, fmt.Errorf("scanorch: node ops not wired"))
			return
		}
		if err := s.Nodes.RecordHeartbeat(r.Context(), hb); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"status": "recorded"})
	}
}

func sweepStalledNodes(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ids, err := s.Nodes.FailoverStalled(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"degraded_nodes": ids, "count": len(ids)})
	}
}

func getRegionQuota(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		region := chi.URLParam(r, "region")
		at, q, err := s.Nodes.IsRegionAtQuota(r.Context(), region, false)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"region": region, "at_quota": at,
			"inflight": q.Inflight, "max": q.MaxConcurrentJobs,
			"reserved_for_platform": q.ReservedForPlatform,
		})
	}
}

func setRegionQuota(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		region := chi.URLParam(r, "region")
		var req struct {
			Max      int `json:"max_concurrent_jobs"`
			Reserved int `json:"reserved_for_platform"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.Nodes.SetRegionQuota(r.Context(), region, req.Max, req.Reserved); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
	}
}

func upsertPullCredential(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		region := chi.URLParam(r, "region")
		var in scanorch.PullCredential
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		in.Region = region
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Nodes.UpsertPullCredential(r.Context(), actor, in); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "stored"})
	}
}

func renderNetworkPolicy(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		region := chi.URLParam(r, "region")
		yaml, err := s.Nodes.RenderNetworkPolicyYAML(r.Context(), region)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(yaml))
	}
}

// ============================================================================
// VS-06 Agent ops
// ============================================================================

func submitAgentCSR(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			CSRPem string `json:"csr_pem"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		// In production the CA is a Vault PKI mount; for now we mint a
		// short-lived self-signed CA on demand. Operators can swap this
		// for a long-lived CA via service injection.
		ca, err := agents.NewSelfSignedCA()
		if err != nil {
			internalErr(w, err)
			return
		}
		cert, fp, err := s.Agents.SubmitCSR(r.Context(), agentID, req.CSRPem, ca)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"certificate_pem": cert, "fingerprint": fp,
		})
	}
}

func rollupAgentTelemetry(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		until := time.Now().UTC()
		since := until.Add(-24 * time.Hour)
		if s := r.URL.Query().Get("since"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				since = t
			}
		}
		written, err := s.Agents.RollupTelemetry(r.Context(), agentID, since, until)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"buckets_written": written})
	}
}

func listAgentTelemetry(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		since := time.Now().UTC().Add(-24 * time.Hour)
		if v := r.URL.Query().Get("since"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				since = t
			}
		}
		buckets, err := s.Agents.ListTelemetry(r.Context(), agentID, since)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"buckets": buckets})
	}
}

func publishAgentBundle(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Manifest    agents.UpdateBundleManifest `json:"manifest"`
			SignatureB64 string                     `json:"signature_b64"`
			SigningKeyID string                     `json:"signing_key_id"`
			Notes        string                     `json:"notes"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, err := s.Agents.PublishBundle(r.Context(), req.Manifest, req.SignatureB64, req.SigningKeyID, req.Notes)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": id})
	}
}

func offerAgentUpdate(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		version := r.URL.Query().Get("current_version")
		offer, err := s.Agents.OfferUpdate(r.Context(), agentID, version)
		if err != nil {
			internalErr(w, err)
			return
		}
		if offer == nil {
			writeJSON(w, http.StatusNoContent, nil)
			return
		}
		writeJSON(w, http.StatusOK, offer)
	}
}

func requestAgentEmergencyStop(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			Reason string `json:"reason"`
			Scope  string `json:"scope"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		stopID, err := s.Agents.RequestEmergencyStop(r.Context(), agentID, req.Reason, req.Scope, actor)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"emergency_stop_id": stopID})
	}
}

func ackAgentEmergencyStop(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stopID, err := uuidParam(r, "stop_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.Agents.AckEmergencyStop(r.Context(), stopID); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "acked"})
	}
}

func emergencyStopSLA(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID, err := uuidParam(r, "agent_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		since := time.Now().UTC().Add(-30 * 24 * time.Hour)
		if v := r.URL.Query().Get("since"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				since = t
			}
		}
		stats, err := s.Agents.EmergencyStopSLAStats(r.Context(), agentID, since)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

// ============================================================================
// VS-07 Findings ops
// ============================================================================

func listFindingClusters(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		out, err := s.Findings.ListClusters(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"clusters": out})
	}
}

func addSeverityOverride(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		var in findings.SeverityOverrideInput
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		rid, err := s.Findings.AddSeverityOverride(r.Context(), tenantID, actor, in)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": rid})
	}
}

func addSuppressionRule(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		var in findings.SuppressionInput
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		rid, err := s.Findings.AddSuppressionRule(r.Context(), tenantID, actor, in)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": rid})
	}
}

func sarifExport(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		f := findings.ListFilter{TenantID: tenantID, Limit: 1000}
		if v := r.URL.Query().Get("severity"); v != "" {
			f.Severity = strings.Split(v, ",")
		}
		if v := r.URL.Query().Get("scanner"); v != "" {
			f.Scanner = v
		}
		body, err := s.Findings.SARIFExport(r.Context(), f)
		if err != nil {
			internalErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Header().Set("Content-Disposition", `attachment; filename="vaultscan-findings.sarif"`)
		_, _ = w.Write(body)
	}
}

// ============================================================================
// VS-08 Evidence ops
// ============================================================================

func verifyEvidenceIntegrity(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		evID, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		ok, err := s.Vault.VerifyIntegrity(r.Context(), evID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"integrity_ok": ok})
	}
}

func enableEvidenceWORM(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		evID, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			Until string `json:"until"`
		}
		_ = decode(r, &req)
		until := time.Now().UTC().Add(7 * 365 * 24 * time.Hour)
		if req.Until != "" {
			if t, err := time.Parse(time.RFC3339, req.Until); err == nil {
				until = t
			}
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Vault.EnableWORM(r.Context(), evID, until, actor); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "worm_enabled", "until": until})
	}
}

func chainOfCustody(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		evID, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		events, err := s.Vault.ChainOfCustody(r.Context(), evID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": events})
	}
}

func chainOfCustodyMarkdown(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		evID, err := uuidParam(r, "evidence_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		md, err := s.Vault.ChainOfCustodyMarkdown(r.Context(), evID)
		if err != nil {
			internalErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/markdown")
		_, _ = w.Write([]byte(md))
	}
}

func rotateTenantKey(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := uuidParam(r, "tenant_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		ver, err := s.Vault.RotateTenantKey(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"new_key_version": ver})
	}
}

func uploadEvidenceWithDEK(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		// Resolve the tenant's partner — that's the correct
		// partner_id for evidence rows tied to this tenant. The
		// previous code used a hardcoded "direct partner" sentinel
		// which was wrong (uploads from MSSP-owned tenants got
		// audited under the platform-direct partner).
		partnerID, err := partnerForTenant(r.Context(), s, tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		evID, err := s.Vault.RecordWithDEK(r.Context(), evidence.PutInput{
			TenantID: tenantID, PartnerID: partnerID,
			Kind: r.URL.Query().Get("kind"),
			ContentType: r.Header.Get("Content-Type"),
			Body: body, UploadedBy: actor,
		})
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": evID})
	}
}

// ============================================================================
// VS-09 Retesting ops
// ============================================================================

func autoLaunchRetest(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		findingID, err := uuidParam(r, "finding_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		retestID, launched, err := s.Retests.AutoLaunchIfEnabled(r.Context(), findingID, actor)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"retest_id": retestID, "launched": launched,
		})
	}
}

func createRetestBatch(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TenantID    uuid.UUID   `json:"tenant_id"`
			Reason      string      `json:"reason"`
			FindingIDs  []uuid.UUID `json:"finding_ids"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		tid, terr := auth.AuthorizeTargetTenant(id, req.TenantID.String())
		if terr != nil {
			forbidden(w, terr.Error())
			return
		}
		batchID, queued, err := s.Retests.CreateBatch(r.Context(), tid, actor, req.Reason, req.FindingIDs)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"batch_id": batchID, "queued": queued,
		})
	}
}

func getRetestBatch(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		batchID, err := uuidParam(r, "batch_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		b, err := s.Retests.GetBatch(r.Context(), batchID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, b)
	}
}

func markRetestBatchItem(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		batchID, err := uuidParam(r, "batch_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		retestID, err := uuidParam(r, "retest_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			State string `json:"state"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.Retests.MarkBatchItem(r.Context(), batchID, retestID, req.State); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "updated"})
	}
}

func getRetestDiff(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		retestID, err := uuidParam(r, "retest_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		// First compute (idempotent) then fetch.
		if _, err := s.Retests.ComputeDiff(r.Context(), retestID); err != nil {
			internalErr(w, err)
			return
		}
		d, err := s.Retests.GetDiff(r.Context(), retestID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func setAutoRetest(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			TenantID uuid.UUID `json:"tenant_id"`
			Enabled  bool      `json:"enabled"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		identity, _ := auth.FromContext(r.Context())
		tid, terr := auth.AuthorizeTargetTenant(identity, req.TenantID.String())
		if terr != nil {
			forbidden(w, terr.Error())
			return
		}
		if err := s.Retests.SetAutoRetestEnabled(r.Context(), tid, req.Enabled); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
	}
}

// ============================================================================
// VS-10 Reporting ops
// ============================================================================

func createReportSchedule(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in reporting.CreateScheduleInput
		if err := decode(r, &in); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		if id != nil {
			a := id.UserID
			in.CreatedBy = &a
		}
		if in.PlatformID == uuid.Nil {
			in.PlatformID = platformConstID()
		}
		if in.PartnerID == uuid.Nil {
			// Fall back to the platform's configured default
			// partner (resolved at boot from
			// VAULTSCAN_DEFAULT_PARTNER_SLUG). If that lookup
			// failed at boot DefaultPartnerID is uuid.Nil and we
			// refuse — better to 400 than silently file the
			// schedule under no partner.
			if s.DefaultPartnerID == uuid.Nil {
				badRequest(w, "partner_id required (default partner not configured)")
				return
			}
			in.PartnerID = s.DefaultPartnerID
		}
		schedID, err := s.Reports.CreateSchedule(r.Context(), in)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"id": schedID})
	}
}

func runDueReports(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ids, err := s.Reports.RunDue(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ran": ids, "count": len(ids)})
	}
}

func complianceMatrix(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		framework := chi.URLParam(r, "framework")
		engagementID, err := uuidParam(r, "engagement_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		matrix, err := s.Reports.ComplianceMatrix(r.Context(), framework, engagementID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"framework": framework, "controls": matrix,
		})
	}
}

func complianceMatrixMarkdown(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		framework := chi.URLParam(r, "framework")
		engagementID, err := uuidParam(r, "engagement_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		md, err := s.Reports.ComplianceMarkdown(r.Context(), framework, engagementID)
		if err != nil {
			internalErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/markdown")
		_, _ = w.Write([]byte(md))
	}
}

// ============================================================================
// VS-11 Integration ops (DLQ)
// ============================================================================

func listDeadLetters(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		integID, err := uuidParam(r, "integration_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		list, err := s.Integrations.ListDeadLetters(r.Context(), integID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dead_letters": list})
	}
}

func replayDeadLetter(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dlqID, err := uuidParam(r, "dlq_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Integrations.Replay(r.Context(), dlqID, actor); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "replayed"})
	}
}

func resolveDeadLetter(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dlqID, err := uuidParam(r, "dlq_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		var req struct {
			Resolution string `json:"resolution"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if err := s.Integrations.MarkDeadLetterResolved(r.Context(), dlqID, req.Resolution); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resolution": req.Resolution})
	}
}

// ============================================================================
// VS-12 Dashboard ops
// ============================================================================

func listDashboardLayouts(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		layouts, err := s.Dashboards.ListLayouts(r.Context(), id.UserID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"layouts": layouts})
	}
}

func saveDashboardLayout(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		var req struct {
			Name      string                `json:"name"`
			Role      string                `json:"role"`
			IsDefault bool                  `json:"is_default"`
			TenantID  *uuid.UUID            `json:"tenant_id,omitempty"`
			Widgets   []dashboards.Widget   `json:"widgets"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		var requestedTenant string
		if req.TenantID != nil {
			requestedTenant = req.TenantID.String()
		}
		tid, terr := auth.AuthorizeOptionalTenant(id, requestedTenant)
		if terr != nil {
			forbidden(w, terr.Error())
			return
		}
		rid, err := s.Dashboards.SaveLayout(r.Context(), id.UserID, tid, req.Name, req.Role, req.Widgets, req.IsDefault)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": rid})
	}
}

func geoScanNodes(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nodes, err := s.Dashboards.GeoNodes(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
	}
}

func complianceSnapshot(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		snaps, err := s.Dashboards.ComplianceForTenant(r.Context(), tenantID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"snapshots": snaps})
	}
}

func dashboardStreamSSE(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.LiveStream == nil {
			internalErr(w, fmt.Errorf("live stream not wired"))
			return
		}
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		channel := r.URL.Query().Get("channel")
		if channel == "" {
			channel = "executive"
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		flusher, ok := w.(http.Flusher)
		if !ok {
			internalErr(w, fmt.Errorf("streaming unsupported"))
			return
		}
		// Disable the http.Server's WriteTimeout (60s in main.go) for
		// this connection — SSE is a long-lived stream and otherwise
		// every client would silently disconnect after a minute. The
		// keepalive ticker below + the request context still bound
		// the connection lifetime.
		rc := http.NewResponseController(w)
		_ = rc.SetWriteDeadline(time.Time{})

		ch, closer, err := s.LiveStream.Subscribe(r.Context(), s.Pool, id.UserID, tenantID, channel)
		if err != nil {
			internalErr(w, err)
			return
		}
		defer closer()

		// keep-alive every 15s + drain events
		ka := time.NewTicker(15 * time.Second)
		defer ka.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ka.C:
				_, _ = w.Write([]byte(":keep-alive\n\n"))
				flusher.Flush()
			case ev, ok := <-ch:
				if !ok {
					return
				}
				b, _ := json.Marshal(ev)
				_, _ = w.Write([]byte("event: " + ev.Type + "\ndata: " + string(b) + "\n\n"))
				flusher.Flush()
			}
		}
	}
}

// ============================================================================
// HS-01 Auth ops
// ============================================================================

func listIPLockouts(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := s.Pool.Query(r.Context(),
			`SELECT host(ip), locked_until, reason, locked_at
			   FROM auth_ip_lockouts WHERE locked_until > now()
			   ORDER BY locked_until DESC LIMIT 200`)
		if err != nil {
			internalErr(w, err)
			return
		}
		defer rows.Close()
		type row struct {
			IP        string    `json:"ip"`
			Until     time.Time `json:"locked_until"`
			Reason    string    `json:"reason"`
			LockedAt  time.Time `json:"locked_at"`
		}
		var out []row
		for rows.Next() {
			var rr row
			if err := rows.Scan(&rr.IP, &rr.Until, &rr.Reason, &rr.LockedAt); err != nil {
				internalErr(w, err)
				return
			}
			out = append(out, rr)
		}
		writeJSON(w, http.StatusOK, map[string]any{"lockouts": out})
	}
}

func unlockIP(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ipStr := chi.URLParam(r, "ip")
		ip := net.ParseIP(ipStr)
		if ip == nil {
			badRequest(w, "invalid ip")
			return
		}
		if err := s.Bruteforce.Unlock(r.Context(), ip); err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "unlocked"})
	}
}

func loadCompromisedPasswords(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		prefix := chi.URLParam(r, "prefix")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		loaded, err := s.Bruteforce.LoadCompromisedBuckets(r.Context(), prefix, body)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"loaded": loaded})
	}
}

// ============================================================================
// HS-02 Audit ops
// ============================================================================

func verifyAuditDeep(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res, err := s.Audit.VerifyDeep(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}
}

func auditTimeline(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := tenantIDFromQuery(r)
		if err != nil {
			writeTenantError(w, err)
			return
		}
		until := time.Now().UTC()
		since := until.Add(-7 * 24 * time.Hour)
		if v := r.URL.Query().Get("since"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				since = t
			}
		}
		if v := r.URL.Query().Get("until"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				until = t
			}
		}
		events, err := s.Audit.Timeline(r.Context(), tenantID, since, until)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"events": events})
	}
}

func shipAuditBatch(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		integID, err := uuidParam(r, "integration_id")
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		max := 500
		if v := r.URL.Query().Get("max"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				max = n
			}
		}
		shipped, lag, err := s.Audit.ShipBatch(r.Context(), integID, max)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"shipped": shipped, "lag": lag})
	}
}

func retentionPolicies(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		policies, err := s.Audit.Policies(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
	}
}

// ============================================================================
// HS-05 Guardrails
// ============================================================================

func maintenanceStatus(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st, err := s.Guardrails.MaintenanceStatus(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, st)
	}
}

func setMaintenance(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Enabled       bool       `json:"enabled"`
			Reason        string     `json:"reason"`
			ExpectedEndAt *time.Time `json:"expected_end_at,omitempty"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		id, _ := auth.FromContext(r.Context())
		var actor *uuid.UUID
		if id != nil {
			a := id.UserID
			actor = &a
		}
		if err := s.Guardrails.SetMaintenance(r.Context(), actor, req.Enabled, req.Reason, req.ExpectedEndAt, clientIP(r)); err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"enabled": req.Enabled})
	}
}

func issueBreakGlass(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := auth.FromContext(r.Context())
		if err != nil {
			internalErr(w, err)
			return
		}
		var req struct {
			Permission string `json:"permission"`
			Reason     string `json:"reason"`
			TTLMinutes int    `json:"ttl_minutes"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		if req.TTLMinutes <= 0 {
			req.TTLMinutes = 15
		}
		tok, raw, err := s.Guardrails.IssueBreakGlass(r.Context(), id.UserID, req.Permission, req.Reason, time.Duration(req.TTLMinutes)*time.Minute)
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"id": tok.ID, "permission": tok.Permission, "expires_at": tok.ExpiresAt,
			"token": raw, // shown ONCE
		})
	}
}

func redeemBreakGlass(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		if err := decode(r, &req); err != nil {
			badRequest(w, err.Error())
			return
		}
		// Route is MFA-gated; identity MUST be present. The previous
		// code defaulted actor=nil if FromContext erred — dangerous
		// because break-glass audit rows would have no attribution
		// (and silently accepting unauthenticated callers if a
		// middleware reorder ever happened).
		id, err := auth.FromContext(r.Context())
		if err != nil || id == nil {
			forbidden(w, "authenticated identity required")
			return
		}
		actor := id.UserID
		perm, issuer, err := s.Guardrails.RedeemBreakGlass(r.Context(), req.Token, &actor, clientIP(r))
		if err != nil {
			badRequest(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"permission": perm, "issuer_id": issuer,
		})
	}
}

func listPolicyRules(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subject := r.URL.Query().Get("subject")
		rules, err := s.Guardrails.Rules(r.Context(), subject)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
	}
}

// ============================================================================
// helpers
// ============================================================================

// tenantIDFromQuery authorizes the requested tenant against the caller's
// identity (tenant-level roles can only target their own tenant) and
// returns the resolved UUID. Previously this just parsed the parameter,
// which made every caller a cross-tenant read primitive.
func tenantIDFromQuery(r *http.Request) (uuid.UUID, error) {
	v := r.URL.Query().Get("tenant_id")
	if v == "" {
		v = r.Header.Get("X-Tenant-Id")
	}
	identity, _ := auth.FromContext(r.Context())
	return auth.AuthorizeTargetTenant(identity, v)
}

// writeTenantError chooses the right status code for the kind of failure
// tenantIDFromQuery can return. Authorization failures must be 403 so
// callers know "you may never do this", not 400 ("payload was malformed").
func writeTenantError(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrCrossTenantForbidden) {
		forbidden(w, err.Error())
		return
	}
	badRequest(w, err.Error())
}

func platformConstID() uuid.UUID {
	return uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
}

// partnerForTenant resolves the partner_id of a tenant. Used by
// handlers that need the partner context (audit attribution,
// evidence row partner_id) but only carry the tenant_id at the
// HTTP layer. Replaces the previous directPartnerID() sentinel
// which was wrong — it pointed every tenant's evidence rows at
// the platform-direct partner regardless of who actually owned
// the tenant.
func partnerForTenant(ctx context.Context, s *Services, tenantID uuid.UUID) (uuid.UUID, error) {
	var partnerID uuid.UUID
	if err := s.Pool.QueryRow(ctx,
		`SELECT partner_id FROM tenants WHERE id=$1`, tenantID).Scan(&partnerID); err != nil {
		return uuid.Nil, err
	}
	return partnerID, nil
}

// retesting + reporting need a method on s, this stub keeps the linter happy
var _ = retesting.RequestInput{}
var _ context.Context = context.Background()
