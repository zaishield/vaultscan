// agent-gateway is the dedicated outbound-only TLS endpoint for internal
// agents (Blueprint §6.3, §27.3). It exposes a small surface: enroll,
// heartbeat, job poll, status, results, artifacts, policy, update.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
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

	"github.com/zaishield/vaultscan/backend/internal/agentgw"
	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/envmode"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/logging"
	"github.com/zaishield/vaultscan/backend/internal/middleware"
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
	// Cross-process delivery for agent-emitted events.
	bus.EnableNotify()
	storage, err := evidence.NewStorageFromConfig(evidence.StorageConfig{
		Backend:          cfg.EvidenceBackend,
		FilesystemRoot:   cfg.EvidenceFilesystemRoot,
		S3Endpoint:       cfg.ObjectStoreURL,
		S3Bucket:         cfg.ObjectStoreBucket,
		S3Region:         cfg.ObjectStoreRegion,
		S3AccessKey:      cfg.ObjectStoreKey,
		S3SecretKey:      cfg.ObjectStoreSecret,
		S3ForcePathStyle: cfg.EvidenceS3ForcePathStyle,
		S3SSE:            cfg.EvidenceS3SSE,
	})
	if err != nil {
		log.Fatal().Err(err).Msg("init evidence storage")
	}
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus, cfg.EvidenceMasterKey,
		evidence.WithStorage(storage),
		evidence.WithURLTTL(cfg.EvidenceURLTTL))
	if err != nil {
		log.Fatal().Err(err).Msg("init vault")
	}
	agentSvc := agents.New(pool.Pool, auditSvc, bus)
	findSvc := findings.New(pool.Pool, auditSvc, bus)

	r := chi.NewRouter()
	r.Use(chiware.Recoverer)
	// Global per-request body cap. Routes that take large payloads
	// (results, artifacts) use their own LimitReader at 64 MiB; this
	// is a defence-in-depth ceiling above that. 128 MiB stops any
	// agent (or attacker that owns one) from posting a GB body and
	// exhausting gateway RAM before the per-route check fires.
	r.Use(middleware.MaxBodySize(128 << 20))

	// Pick the agent-auth strategy. VAULTSCAN_AGENT_GW_TLS:
	//
	//   on   / true  — Real mTLS REQUIRED. Trust pool must be populated.
	//                  Cert+key must be supplied via VAULTSCAN_AGENT_GW_CERT
	//                  + VAULTSCAN_AGENT_GW_KEY (no auto-mint). Any setup
	//                  failure is fatal.
	//
	//   off  / false — Dev-header auth (X-Agent-Id). REFUSED in production
	//                  mode (cfg.Env=production); ops must use 'on'.
	//
	//   auto         — DEV ONLY. mTLS if trust pool is populated and certs
	//                  load; otherwise self-sign + dev-header auth. REFUSED
	//                  in production mode.
	//
	//   (unset)      — Defaults to 'auto' for dev convenience, 'on' in
	//                  production mode (fail-closed).
	tlsMode := strings.ToLower(strings.TrimSpace(os.Getenv("VAULTSCAN_AGENT_GW_TLS")))
	isProd := envmode.IsProduction(cfg.Env)
	if tlsMode == "" {
		if isProd {
			tlsMode = "on"
		} else {
			tlsMode = "auto"
		}
	}

	// Production guard: refuse any insecure mode.
	if isProd && (tlsMode == "off" || tlsMode == "false" || tlsMode == "auto") {
		log.Fatal().
			Str("tls_mode", tlsMode).
			Msg("agent-gateway refusing to start: VAULTSCAN_AGENT_GW_TLS must be 'on' in production")
	}

	var authMiddleware func(http.Handler) http.Handler
	var tlsConfig *tls.Config
	switch tlsMode {
	case "on", "true":
		// Strict mode: every failure is fatal. Never fall back to headers.
		verifier, err := agentgw.NewCertVerifier(ctx, pool.Pool)
		if err != nil {
			log.Fatal().Err(err).Msg("mTLS=on but trust pool unavailable — populate agent_ca_certificates")
		}
		if cfg.AgentGatewayCertPath == "" || cfg.AgentGatewayKeyPath == "" {
			log.Fatal().Msg("mTLS=on requires VAULTSCAN_AGENT_GW_CERT + VAULTSCAN_AGENT_GW_KEY")
		}
		serverCert, serverKey, err := loadGatewayCertFromDisk(cfg)
		if err != nil {
			log.Fatal().Err(err).Msg("load gateway cert/key")
		}
		tlsConfig, err = agentgw.BuildTLSConfig(serverCert, serverKey, verifier)
		if err != nil {
			log.Fatal().Err(err).Msg("build TLS config")
		}
		authMiddleware = agentgw.IdentityFromTLSMiddleware(pool.Pool)
		log.Info().
			Str("cert", cfg.AgentGatewayCertPath).
			Msg("agent-gateway running with real mTLS (RequireAndVerifyClientCert + fingerprint check)")

	case "off", "false":
		if isProd {
			log.Fatal().Msg("dev-header mode is forbidden in production")
		}
		authMiddleware = agentAuthMiddleware(pool.Pool)
		log.Warn().Msg("agent-gateway in dev-header mode — production MUST set VAULTSCAN_AGENT_GW_TLS=on")

	case "auto":
		if isProd {
			log.Fatal().Msg("auto mode is forbidden in production — set VAULTSCAN_AGENT_GW_TLS=on")
		}
		verifier, vErr := agentgw.NewCertVerifier(ctx, pool.Pool)
		if vErr != nil {
			log.Warn().Err(vErr).Msg("dev: trust pool not configured, using dev-header auth")
			authMiddleware = agentAuthMiddleware(pool.Pool)
			break
		}
		serverCert, serverKey, cErr := loadOrGenerateGatewayCert(cfg)
		if cErr != nil {
			log.Warn().Err(cErr).Msg("dev: cert load/mint failed, using dev-header auth")
			authMiddleware = agentAuthMiddleware(pool.Pool)
			break
		}
		tlsConfig, err = agentgw.BuildTLSConfig(serverCert, serverKey, verifier)
		if err != nil {
			log.Warn().Err(err).Msg("dev: TLS config build failed, using dev-header auth")
			authMiddleware = agentAuthMiddleware(pool.Pool)
			break
		}
		authMiddleware = agentgw.IdentityFromTLSMiddleware(pool.Pool)
		log.Info().Msg("agent-gateway running with auto-mode mTLS")

	default:
		log.Fatal().Str("mode", tlsMode).
			Msg("unknown VAULTSCAN_AGENT_GW_TLS mode (want: on|off|auto)")
	}

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})

	// Fleet-wide telemetry exposition for Prometheus. Single scrape
	// target aggregates per-agent state from the DB (rather than
	// scraping each agent — which would punch through customer
	// network policies). See internal/agentgw/fleet_metrics.go.
	fleet := agentgw.NewFleetMetrics(pool.Pool)
	r.Get("/agent-fleet-metrics", fleet.Handler())

	// Orchestrator public key — the agent's verifier needs this to
	// validate per-job RSA-PSS signatures. We proxy the read to the
	// API so the API stays the single source of truth for the
	// signing key (and the gateway doesn't have to be re-signed
	// when the key rotates).
	apiBase := strings.TrimRight(cfg.APIPublicURL(), "/")
	r.Get("/api/v1/orchestrator/public-key", func(w http.ResponseWriter, r *http.Request) {
		if apiBase == "" {
			writeJSON(w, 500, map[string]string{"error": "VAULTSCAN_API_PUBLIC_URL not configured"})
			return
		}
		req, _ := http.NewRequestWithContext(r.Context(), "GET",
			apiBase+"/api/v1/orchestrator/public-key", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "upstream api unreachable: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
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

	// All other endpoints require a per-agent identity. The middleware is
	// either mTLS-derived (production) or dev-headers (single-node compose).
	r.Group(func(r chi.Router) {
		r.Use(authMiddleware)

		r.Post("/api/v1/agents/heartbeat", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentgw.AgentFromContext(r.Context())
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
			agentID := agentgw.AgentFromContext(r.Context())
			n, _ := strconv.Atoi(r.URL.Query().Get("max"))
			out, err := agentSvc.PollJobs(r.Context(), agentID, n)
			if err != nil {
				writeJSON(w, 500, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 200, map[string]any{"items": out})
		})

		r.Post("/api/v1/agents/jobs/{job_id}/status", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentgw.AgentFromContext(r.Context())
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
			agentID := agentgw.AgentFromContext(r.Context())
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
			// Cap raw scanner output at 64 MiB. Without this an
			// agent (or an attacker that owns one) can post a GB-
			// sized body and exhaust the gateway's RAM. The
			// scanner-side runner already enforces the same cap;
			// this is defense in depth.
			body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "body read failed"})
				return
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

			ev, err := vault.Record(r.Context(), evidence.PutInput{
				TenantID: tenantID, PartnerID: partnerID,
				EngagementID: &engagementID, ScanJobID: &jobID,
				Kind: "raw_output", ContentType: "application/octet-stream", Body: body,
			})
			if err != nil || ev == nil {
				writeJSON(w, 500, map[string]string{"error": "evidence persist failed"})
				return
			}

			// parsers.Lookup (not Registry directly) so the universal
			// MaxParserInputBytes + MaxFindingsPerParse DoS guards
			// apply. A hostile agent posting a 1 GiB JSON would
			// otherwise bypass them and OOM the gateway.
			parser, ok := parsers.Lookup(tool)
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
			agentID := agentgw.AgentFromContext(r.Context())
			jobID, err := uuid.Parse(chi.URLParam(r, "job_id"))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": "body read failed"})
				return
			}
			var tenantID, partnerID, engagementID uuid.UUID
			err = pool.Pool.QueryRow(r.Context(),
				`SELECT tenant_id, partner_id, engagement_id FROM scan_jobs WHERE id=$1 AND agent_id=$2`,
				jobID, agentID).Scan(&tenantID, &partnerID, &engagementID)
			if err != nil {
				writeJSON(w, 404, map[string]string{"error": "job not found"})
				return
			}
			ev, err := vault.Record(r.Context(), evidence.PutInput{
				TenantID: tenantID, PartnerID: partnerID,
				EngagementID: &engagementID, ScanJobID: &jobID,
				Kind:        r.URL.Query().Get("kind"),
				ContentType: r.Header.Get("Content-Type"),
				Body:        body,
			})
			if err != nil || ev == nil {
				writeJSON(w, 500, map[string]string{"error": "evidence persist failed"})
				return
			}
			writeJSON(w, 200, map[string]any{"evidence_id": ev.ID})
		})

		r.Get("/api/v1/agents/policy", func(w http.ResponseWriter, r *http.Request) {
			agentID := agentgw.AgentFromContext(r.Context())
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
		// Default 1 MiB is generous for agent headers (mTLS metadata,
		// X-Agent-Id, content-type). Cap tightly to thwart header-bomb
		// DoS — same rationale as cmd/api/main.go.
		MaxHeaderBytes: 32 * 1024,
		TLSConfig:      tlsConfig,
	}
	go func() {
		log.Info().Str("addr", cfg.AgentGatewayAddr).Bool("mtls", tlsConfig != nil).
			Msg("agent-gateway listening")
		var err error
		if tlsConfig != nil {
			// ListenAndServeTLS ignores cert/key paths when Server.TLSConfig
			// already has Certificates loaded — pass empty strings.
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// agentAuthMiddleware is the dev-mode header path: accept X-Agent-Id +
// X-Agent-Cert-Fingerprint when mTLS isn't configured. Production
// deployments MUST run the gateway with VAULTSCAN_AGENT_GW_TLS=on so the
// real mTLS verifier (agentgw.IdentityFromTLSMiddleware) takes over.
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
			next.ServeHTTP(w, r.WithContext(agentgw.WithAgent(r.Context(), id)))
		})
	}
}

// loadOrGenerateGatewayCert returns the server cert+key the gateway
// presents to agents. If VAULTSCAN_AGENT_GW_CERT and ..._KEY env vars
// point at PEM files, those win. Otherwise we mint an in-process self-
// signed cert valid for 90 days — dev only; production must provide a
// CA-signed cert via cert-manager / k8s Secret.
// loadGatewayCertFromDisk loads the server cert+key from configured
// paths. Used only in mTLS=on mode (production). Returns error if either
// path is empty or unreadable — never auto-mints.
func loadGatewayCertFromDisk(cfg *config.Config) ([]byte, []byte, error) {
	if cfg.AgentGatewayCertPath == "" || cfg.AgentGatewayKeyPath == "" {
		return nil, nil, errors.New("AgentGatewayCertPath and AgentGatewayKeyPath must be set")
	}
	certPEM, err := os.ReadFile(cfg.AgentGatewayCertPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(cfg.AgentGatewayKeyPath)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, nil
}


func loadOrGenerateGatewayCert(cfg *config.Config) ([]byte, []byte, error) {
	if cfg.AgentGatewayCertPath != "" && cfg.AgentGatewayKeyPath != "" {
		certPEM, err := os.ReadFile(cfg.AgentGatewayCertPath)
		if err != nil {
			return nil, nil, err
		}
		keyPEM, err := os.ReadFile(cfg.AgentGatewayKeyPath)
		if err != nil {
			return nil, nil, err
		}
		return certPEM, keyPEM, nil
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "vaultscan-agent-gateway-dev"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"agent-gateway", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return certPEM, keyPEM, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
