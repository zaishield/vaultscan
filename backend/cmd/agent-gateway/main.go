// agent-gateway is the dedicated outbound-only TLS endpoint for internal
// agents (Blueprint §6.3, §27.3). It exposes a small surface: enroll,
// heartbeat, job poll, status, results, artifacts, policy, update.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chiware "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/parsers"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)
	ctx := context.Background()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("open db")
	}
	defer pool.Close()

	auditSvc := audit.New(pool.Pool)
	bus := eventbus.New(pool.Pool)
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus, cfg.EvidenceMasterKey,
		evidence.WithURLTTL(cfg.EvidenceURLTTL))
	if err != nil {
		log.Fatal().Err(err).Msg("init vault")
	}
	agentSvc := agents.New(pool.Pool, auditSvc, bus)
	findSvc := findings.New(pool.Pool, auditSvc, bus)

	r := chi.NewRouter()
	r.Use(chiware.Recoverer)

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	// Enrollment uses the one-time token issued at provisioning.
	r.Post("/api/v1/agents/{agent_id}/enroll", func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(chi.URLParam(r, "agent_id"))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad agent id"})
			return
		}
		var req struct {
			Token       string `json:"token"`
			CertPEM     string `json:"cert_pem"`
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if err := agentSvc.Enroll(r.Context(), id, req.Token, req.CertPEM, req.Fingerprint); err != nil {
			writeJSON(w, 401, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "enrolled"})
	})

	// All other endpoints require a per-agent header. In production this is
	// enforced by mTLS; in dev we accept X-Agent-Id + X-Agent-Cert-Fingerprint.
	r.Group(func(r chi.Router) {
		r.Use(agentAuthMiddleware(pool.Pool))

		r.Post("/api/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentFromCtx(r)
			var req struct {
				CPUPercent     float64        `json:"cpu_percent"`
				MemoryPercent  float64        `json:"memory_percent"`
				DiskPercent    float64        `json:"disk_percent"`
				RunningJobs    int            `json:"running_jobs"`
				QueueDepth     int            `json:"queue_depth"`
				Version        string         `json:"version"`
				Payload        map[string]any `json:"payload"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			if err := agentSvc.Heartbeat(r.Context(), agents.Heartbeat{
				AgentID: agentID, CPUPercent: req.CPUPercent, MemoryPercent: req.MemoryPercent,
				DiskPercent: req.DiskPercent, RunningJobs: req.RunningJobs,
				QueueDepth: req.QueueDepth, Version: req.Version, Payload: req.Payload,
			}); err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]string{"status": "ack"})
		})

		r.Get("/api/v1/agents/jobs/poll", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentFromCtx(r)
			n, _ := strconv.Atoi(r.URL.Query().Get("max"))
			out, err := agentSvc.PollJobs(r.Context(), agentID, n)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"items": out})
		})

		r.Post("/api/v1/agents/jobs/{job_id}/status", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentFromCtx(r)
			jobID, err := uuid.Parse(chi.URLParam(r, "job_id"))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			var req struct {
				State string `json:"state"`  // running | succeeded | failed | killed
				Error string `json:"error"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			_, _ = pool.Pool.Exec(r.Context(),
				`UPDATE scan_jobs SET status=$2, updated_at=now(),
				                       started_at=COALESCE(started_at, CASE WHEN $2='running' THEN now() END),
				                       completed_at=CASE WHEN $2 IN ('succeeded','failed','killed') THEN now() ELSE completed_at END
				   WHERE id=$1 AND agent_id=$3`,
				jobID, req.State, agentID)
			_, _ = pool.Pool.Exec(r.Context(),
				`UPDATE agent_job_queue
				    SET state=CASE WHEN $2 IN ('succeeded','failed','killed') THEN 'done' ELSE 'acknowledged' END,
				        acknowledged_at=now(),
				        completed_at=CASE WHEN $2 IN ('succeeded','failed','killed') THEN now() END
				  WHERE scan_job_id=$1 AND agent_id=$3`, jobID, req.State, agentID)
			writeJSON(w, 200, map[string]string{"status": "ok"})
		})

		r.Post("/api/v1/agents/jobs/{job_id}/results", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentFromCtx(r)
			jobID, err := uuid.Parse(chi.URLParam(r, "job_id"))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			tool := r.URL.Query().Get("tool")
			if tool == "" {
				writeJSON(w, 400, map[string]string{"error": "tool query required"})
				return
			}
			body := make([]byte, 0, 64*1024)
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					body = append(body, buf[:n]...)
				}
				if err != nil {
					break
				}
			}
			// Resolve tenant/partner/engagement context for the job.
			var tenantID, partnerID, engagementID, platformID uuid.UUID
			var assetID *uuid.UUID
			err = pool.Pool.QueryRow(r.Context(),
				`SELECT tenant_id, partner_id, engagement_id, platform_id
				   FROM scan_jobs WHERE id=$1 AND agent_id=$2`, jobID, agentID).
				Scan(&tenantID, &partnerID, &engagementID, &platformID)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": "job not found for agent"})
				return
			}

			ev, _ := vault.Record(r.Context(), evidence.PutInput{
				TenantID: tenantID, PartnerID: partnerID,
				EngagementID: &engagementID, ScanJobID: &jobID,
				Kind: "raw_output", ContentType: "application/octet-stream", Body: body,
			})

			parser, ok := parsers.Registry[tool]
			if !ok {
				writeJSON(w, 200, map[string]any{"evidence_id": ev.ID, "ingested_findings": 0,
					"note": "no parser available for tool"})
				return
			}
			ingested, err := parser(parsers.Context{
				PlatformID: platformID, PartnerID: partnerID, TenantID: tenantID,
				EngagementID: engagementID, ScanJobID: &jobID, AssetID: assetID,
			}, body)
			if err != nil {
				writeJSON(w, 200, map[string]any{"evidence_id": ev.ID, "parse_error": err.Error()})
				return
			}
			ingestedCount := 0
			for _, in := range ingested {
				if _, _, err := findSvc.Upsert(r.Context(), in); err == nil {
					ingestedCount++
				}
			}
			writeJSON(w, 200, map[string]any{"evidence_id": ev.ID, "ingested_findings": ingestedCount})
		})

		r.Post("/api/v1/agents/jobs/{job_id}/artifacts", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentFromCtx(r)
			jobID, err := uuid.Parse(chi.URLParam(r, "job_id"))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			body := make([]byte, 0, 64*1024)
			buf := make([]byte, 32*1024)
			for {
				n, err := r.Body.Read(buf)
				if n > 0 {
					body = append(body, buf[:n]...)
				}
				if err != nil {
					break
				}
			}
			var tenantID, partnerID, engagementID uuid.UUID
			err = pool.Pool.QueryRow(r.Context(),
				`SELECT tenant_id, partner_id, engagement_id FROM scan_jobs WHERE id=$1 AND agent_id=$2`,
				jobID, agentID).Scan(&tenantID, &partnerID, &engagementID)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": "job not found"})
				return
			}
			ev, _ := vault.Record(r.Context(), evidence.PutInput{
				TenantID: tenantID, PartnerID: partnerID,
				EngagementID: &engagementID, ScanJobID: &jobID,
				Kind:        r.URL.Query().Get("kind"),
				ContentType: r.Header.Get("Content-Type"),
				Body:        body,
			})
			writeJSON(w, 200, map[string]any{"evidence_id": ev.ID})
		})

		r.Get("/api/v1/agents/policy", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentFromCtx(r)
			p, err := agentSvc.Policy(r.Context(), agentID)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, p)
		})

		r.Get("/api/v1/agents/update", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"version": "1.0.0", "url": "", "sha256": ""})
		})
	})

	srv := &http.Server{
		Addr:              cfg.AgentGatewayAddr,
		Handler:           r,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		log.Info().Str("addr", cfg.AgentGatewayAddr).Msg("agent-gateway listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("agent gateway")
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	shctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shctx)
}

// agentAuthMiddleware verifies the agent's identity. In production the gateway
// terminates mTLS and uses the client cert; for the dev build we accept the
// agent id + fingerprint headers as long as they match a stored certificate.
type agentCtxKey int

const agentIDCtx agentCtxKey = 1

func agentFromCtx(r *http.Request) uuid.UUID {
	if v := r.Context().Value(agentIDCtx); v != nil {
		if id, ok := v.(uuid.UUID); ok {
			return id
		}
	}
	return uuid.Nil
}

// agentAuthMiddleware verifies the agent identity. Production: terminate
// mTLS at the gateway and read the client cert SAN. Dev: accept the agent id
// header plus a cert fingerprint that matches the stored certificate.
func agentAuthMiddleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			idStr := strings.TrimSpace(r.Header.Get("X-Agent-Id"))
			fp := strings.TrimSpace(r.Header.Get("X-Agent-Cert-Fingerprint"))
			if idStr == "" || fp == "" {
				writeJSON(w, 401, map[string]string{"error": "missing X-Agent-Id / X-Agent-Cert-Fingerprint"})
				return
			}
			id, err := uuid.Parse(idStr)
			if err != nil {
				writeJSON(w, 401, map[string]string{"error": "bad agent id"})
				return
			}
			var stored string
			if err := pool.QueryRow(r.Context(), `
				SELECT fingerprint FROM agent_certificates
				 WHERE agent_id=$1 AND revoked_at IS NULL
				 ORDER BY issued_at DESC LIMIT 1`, id).Scan(&stored); err != nil {
				writeJSON(w, 401, map[string]string{"error": "no active certificate"})
				return
			}
			if stored != fp {
				writeJSON(w, 401, map[string]string{"error": "fingerprint mismatch"})
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), agentIDCtx, id))
			next.ServeHTTP(w, r)
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
