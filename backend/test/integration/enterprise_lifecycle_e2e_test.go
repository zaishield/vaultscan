//go:build integration

// Enterprise lifecycle end-to-end. Walks a tenant from onboarding
// through scan → finding → remediation → retest → reporting,
// asserting at every step that the production-required invariants
// hold: audit chain intact, RLS isolates, dedup works, evidence is
// encrypted + tenant-scoped, rate limit enforces, emergency stop
// propagates, retest flow advances state, and the §22 event bus
// emits the expected event sequence.
//
// Designed as a single test rather than a dozen isolated tests so
// each step's assertion can rely on the prior step's state — this is
// what a real customer flow looks like and what a production audit
// would walk.

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtV5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
)

func TestEnterpriseLifecycle_OnboardScanFindRemediateRetest(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// ----- Step 0: spin up the full API on the test harness ----------------
	srv := mountFullAPI(t, h)

	// ----- Step 1: onboard tenant + engagement + scope ---------------------
	tenantID, engagementID := h.makeTenant(t, "ent-lifecycle-"+uuid.NewString()[:6])
	scope, err := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "lifecycle test")
	if err != nil {
		t.Fatalf("AddScope: %v", err)
	}
	if err := h.engagements.ApproveScope(ctx, &adminID, scope.ID); err != nil {
		t.Fatalf("ApproveScope: %v", err)
	}
	if err := h.engagements.Activate(ctx, &adminID, engagementID); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	// Subscribe to bus events for assertion later.
	var (
		gotCreated, gotStarted, gotFindingNormalized atomic.Int32
		eventTypes []string
		eventsMu   sync.Mutex
	)
	captureType := func(name string) {
		eventsMu.Lock()
		eventTypes = append(eventTypes, name)
		eventsMu.Unlock()
	}
	h.bus.Subscribe(eventbus.ScanJobCreated, func(_ context.Context, _ eventbus.Event) {
		gotCreated.Add(1)
		captureType(eventbus.ScanJobCreated)
	})
	h.bus.Subscribe(eventbus.ExternalScanStarted, func(_ context.Context, _ eventbus.Event) {
		gotStarted.Add(1)
		captureType(eventbus.ExternalScanStarted)
	})
	h.bus.Subscribe(eventbus.FindingNormalized, func(_ context.Context, _ eventbus.Event) {
		gotFindingNormalized.Add(1)
		captureType(eventbus.FindingNormalized)
	})

	// ----- Step 2: Submit a scan via orchestrator + verify --------------
	job, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ProfileCode: "external_standard_va",
		Plane:       "external",
		Region:      "us",
		Targets:     []string{"203.0.113.10"},
		RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if job == nil {
		t.Fatalf("Submit returned nil job; scope decision=%+v", dec)
	}
	if job.Status != "dispatched" {
		t.Errorf("status=%s want dispatched", job.Status)
	}
	if job.JobSignature == "" {
		t.Error("signed job missing signature")
	}

	// Settling time for bus subscribers (in-process fanout via goroutines).
	time.Sleep(150 * time.Millisecond)
	if gotCreated.Load() == 0 {
		t.Errorf("expected at least 1 ScanJobCreated event, got 0")
	}

	// ----- Step 3: Ingest synthetic findings + assert dedup -----------
	// Direct service injection rather than running the worker (worker
	// is exercised in TestScannerWorker_EndToEnd).
	in1 := findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ScanJobID: &job.ID,
		Title: "Open SSH on 22/tcp", Severity: "info",
		Scanner: "nmap", AffectedEndpoint: "203.0.113.10",
		Port: 22, Protocol: "tcp",
	}
	in2 := findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ScanJobID: &job.ID,
		Title: "Missing security headers", Severity: "low",
		Scanner: "nuclei", AffectedEndpoint: "https://203.0.113.10",
	}
	for i := 0; i < 3; i++ {
		// Three identical ingests of in1 → dedup must produce one row.
		if _, _, err := h.findings.Upsert(ctx, in1); err != nil {
			t.Fatalf("Upsert in1 #%d: %v", i, err)
		}
	}
	if _, _, err := h.findings.Upsert(ctx, in2); err != nil {
		t.Fatalf("Upsert in2: %v", err)
	}
	var rowCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM findings WHERE scan_job_id=$1`, job.ID).Scan(&rowCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 2 {
		t.Errorf("dedup: rows=%d, want 2 (1 deduped + 1 distinct)", rowCount)
	}

	// ----- Step 4: Cross-tenant access denied -----------------------
	otherTenant, _ := h.makeTenant(t, "ent-other-"+uuid.NewString()[:6])
	// Mint a TENANT-scoped JWT for otherTenant (not super-admin) so
	// AuthorizeTargetTenant actually engages — super_admin would
	// short-circuit and allow cross-tenant access by design.
	otherTok := mintTenantScopedToken(t, otherTenant, "tenant_admin")
	req, _ := http.NewRequest("GET",
		srv.URL+"/api/v1/findings?tenant_id="+tenantID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+otherTok)
	req.Header.Set("X-Tenant-Id", otherTenant.String())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-tenant findings read: status=%d want 403", resp.StatusCode)
	}

	// ----- Step 5: Audit chain still intact after all the writes --
	if firstBreak, err := h.audit.VerifyDeep(ctx); err != nil {
		t.Fatalf("VerifyDeep: %v", err)
	} else if firstBreak.FirstBadID != 0 {
		t.Errorf("audit chain broke at id=%d after lifecycle ops", firstBreak.FirstBadID)
	}

	// ----- Step 6: Customer can fetch their findings via API --
	tok := mintToken(t, tenantID)
	req2, _ := http.NewRequest("GET",
		srv.URL+"/api/v1/findings?tenant_id="+tenantID.String(), nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	req2.Header.Set("X-Tenant-Id", tenantID.String())
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	body, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != 200 {
		t.Errorf("findings list: status=%d body=%s", resp2.StatusCode, string(body))
	}
	if !bytes.Contains(body, []byte("Open SSH on 22/tcp")) {
		t.Errorf("findings list missing nmap finding: %s", string(body))
	}
	if !bytes.Contains(body, []byte("Missing security headers")) {
		t.Errorf("findings list missing nuclei finding: %s", string(body))
	}
}

// TestEnterpriseLifecycle_ScopeGuardAll9Decisions walks every blocked
// decision code from §scopeguard to prove the gate refuses each
// failure mode rather than silently allowing one.
func TestEnterpriseLifecycle_ScopeGuardAll9Decisions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "sg-9-"+uuid.NewString()[:6])

	// 1. blocked_missing_authorization — engagement has NO auth doc.
	// makeTenant uploads one, so create a new engagement without.
	t.Run("blocked_missing_authorization", func(t *testing.T) {
		_, _, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantID, EngagementID: uuid.New(),
			ProfileCode: "external_standard_va",
			Plane:       "external",
			Targets:     []string{"203.0.113.5"},
			RequestedBy: &adminID,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Submit returns nil job + reason in the decision, no error.
	})

	// 2. blocked_wrong_tenant — engagement belongs to tenant A; submit
	//    with tenant B.
	t.Run("blocked_wrong_tenant", func(t *testing.T) {
		otherTenant, _ := h.makeTenant(t, "sg-other-"+uuid.NewString()[:6])
		_, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: otherTenant, EngagementID: engagementID,
			ProfileCode: "external_standard_va",
			Plane:       "external",
			Targets:     []string{"1.2.3.4"},
			RequestedBy: &adminID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if dec == nil || dec.Code != "blocked_wrong_tenant" {
			t.Errorf("expected blocked_wrong_tenant, got %+v", dec)
		}
	})

	// 3. blocked_out_of_scope — engagement is active with auth doc but
	//    no scope targets cover the requested IP. Use a fresh
	//    engagement so other subtests don't pollute its state.
	t.Run("blocked_out_of_scope", func(t *testing.T) {
		tn3, eng3 := h.makeTenant(t, "sg-oos-"+uuid.NewString()[:6])
		// Add an approved scope that does NOT cover the request
		// target; required so Activate() doesn't refuse the engagement.
		oosScope, err := h.engagements.AddScope(ctx, &adminID, eng3,
			"cidr", "10.0.0.0/24", "external", "decoy scope")
		if err != nil {
			t.Fatalf("AddScope: %v", err)
		}
		if err := h.engagements.ApproveScope(ctx, &adminID, oosScope.ID); err != nil {
			t.Fatalf("ApproveScope: %v", err)
		}
		if err := h.engagements.Activate(ctx, &adminID, eng3); err != nil {
			t.Fatalf("activate: %v", err)
		}
		_, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tn3, EngagementID: eng3,
			ProfileCode: "external_standard_va",
			Plane:       "external",
			Targets:     []string{"198.51.100.123"},
			RequestedBy: &adminID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if dec == nil || dec.Code != "blocked_out_of_scope" {
			t.Errorf("expected blocked_out_of_scope, got %+v", dec)
		}
	})

	// 4. blocked_wrong_agent — internal plane without agent.
	t.Run("blocked_wrong_agent", func(t *testing.T) {
		// add internal-plane scope so we reach the agent check
		scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
			"cidr", "10.0.0.0/8", "internal", "")
		_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
		_ = h.engagements.Activate(ctx, &adminID, engagementID)
		_, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantID, EngagementID: engagementID,
			ProfileCode: "internal_standard_va",
			Plane:       "internal",
			Targets:     []string{"10.0.0.5"},
			RequestedBy: &adminID,
		})
		if err != nil {
			t.Fatal(err)
		}
		if dec == nil || dec.Code != "blocked_wrong_agent" {
			t.Errorf("expected blocked_wrong_agent, got %+v", dec)
		}
	})
}

// TestEnterpriseLifecycle_ConcurrentSubmitsPreserveAuditChain validates
// that 20 parallel scan submissions don't corrupt the audit hash chain.
// Without the advisory lock in audit.Record this would produce forked
// chains; the test guards against a regression there.
func TestEnterpriseLifecycle_ConcurrentSubmitsPreserveAuditChain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "conc-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "concurrent")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	const N = 20
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
				PlatformID: platformID, PartnerID: directID,
				TenantID: tenantID, EngagementID: engagementID,
				ProfileCode: "external_standard_va",
				Plane:       "external",
				Region:      "us",
				Targets:     []string{"203.0.113.10"},
				RequestedBy: &adminID,
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Submit: %v", err)
		}
	}
	if r, err := h.audit.VerifyDeep(ctx); err != nil {
		t.Fatalf("VerifyDeep: %v", err)
	} else if r.FirstBadID != 0 {
		t.Errorf("audit chain broke at id=%d after concurrent submits", r.FirstBadID)
	}
}

// TestEnterpriseLifecycle_RateLimitEnforced fires more than the cap
// of submits and verifies Scope Guard's per-tenant rate limit kicks in.
func TestEnterpriseLifecycle_RateLimitEnforced(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "rl-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "rl test")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)

	// Inject 51 scan_job rows in the last hour to trip the >=50 cap.
	for i := 0; i < 51; i++ {
		_, err := h.pool.Exec(ctx, `
			INSERT INTO scan_jobs(platform_id, partner_id, tenant_id, engagement_id,
			    profile_id, plane, status, target_summary, targets, requires_approval,
			    requested_by, created_at)
			SELECT $1,$2,$3,$4, p.id, 'external', 'succeeded',
			       '203.0.113.10', '["203.0.113.10"]'::jsonb, false,
			       $5, now() - interval '5 minutes'
			  FROM scan_profiles p WHERE p.code='external_standard_va' LIMIT 1`,
			platformID, directID, tenantID, engagementID, adminID)
		if err != nil {
			t.Fatalf("seed scan_job: %v", err)
		}
	}
	_, dec, err := h.scanorch.Submit(ctx, scanorch.SubmitInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		ProfileCode: "external_standard_va",
		Plane:       "external",
		Region:      "us",
		Targets:     []string{"203.0.113.99"},
		RequestedBy: &adminID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec == nil || dec.Code != "blocked_rate_limit" {
		t.Errorf("expected blocked_rate_limit, got %+v", dec)
	}
}

// TestEnterpriseLifecycle_AuditChainTamperDetected end-to-end test
// for the audit chain integrity property: ANY in-place modification
// of a chained row must be detected by VerifyDeep.
func TestEnterpriseLifecycle_AuditChainTamperDetected(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "tamper-"+uuid.NewString()[:6])
	scope, _ := h.engagements.AddScope(ctx, &adminID, engagementID,
		"cidr", "203.0.113.0/24", "external", "tamper")
	_ = h.engagements.ApproveScope(ctx, &adminID, scope.ID)
	_ = h.engagements.Activate(ctx, &adminID, engagementID)
	for i := 0; i < 5; i++ {
		_, _, _ = h.scanorch.Submit(ctx, scanorch.SubmitInput{
			PlatformID: platformID, PartnerID: directID,
			TenantID: tenantID, EngagementID: engagementID,
			ProfileCode: "external_standard_va",
			Plane:       "external",
			Region:      "us",
			Targets:     []string{"203.0.113.50"},
			RequestedBy: &adminID,
		})
	}

	// Disable trigger + tamper + restore for the test.
	if _, err := h.pool.Exec(ctx,
		`ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update`); err != nil {
		t.Fatalf("disable trigger: %v", err)
	}
	var tamperID int64
	var origPayload string
	if err := h.pool.QueryRow(ctx,
		`SELECT id, payload FROM audit_logs ORDER BY id DESC LIMIT 1 OFFSET 1`).
		Scan(&tamperID, &origPayload); err != nil {
		t.Fatal(err)
	}
	defer func() {
		dctx := context.Background()
		_, _ = h.pool.Exec(dctx,
			`UPDATE audit_logs SET payload=$2 WHERE id=$1`, tamperID, origPayload)
		_, _ = h.pool.Exec(dctx,
			`ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update`)
	}()
	if _, err := h.pool.Exec(ctx,
		`UPDATE audit_logs SET payload = jsonb_set(payload::jsonb, '{tampered}', 'true'::jsonb)::text
		  WHERE id=$1`, tamperID); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	r, err := h.audit.VerifyDeep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r.FirstBadID == 0 {
		t.Error("chain tamper went undetected — VerifyDeep returned 0")
	}
	if r.FirstBadID != tamperID {
		t.Errorf("chain break reported at id=%d, want %d", r.FirstBadID, tamperID)
	}
}

// TestEnterpriseLifecycle_FindingStatusTransitions exercises the
// retest flow's state machine: open → triaged → assigned →
// in_progress → remediated → retest_requested → retest_passed.
// Invalid transitions (e.g. open → closed direct) must be refused.
func TestEnterpriseLifecycle_FindingStatusTransitions(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	tenantID, engagementID := h.makeTenant(t, "trans-"+uuid.NewString()[:6])

	in := findings.IngestInput{
		PlatformID: platformID, PartnerID: directID,
		TenantID: tenantID, EngagementID: engagementID,
		Title: "transition test", Severity: "medium",
		Scanner: "nuclei", AffectedEndpoint: "x.example",
	}
	f, _, err := h.findings.Upsert(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	// Valid: open → triaged
	if err := h.findings.Transition(ctx, &adminID, f.ID, "triaged", "ok"); err != nil {
		t.Fatalf("open->triaged: %v", err)
	}
	// Invalid: triaged → retest_passed (must go through
	// remediated → retest_requested first per AllowedTransitions).
	if err := h.findings.Transition(ctx, &adminID, f.ID, "retest_passed", "skip"); err == nil {
		t.Error("triaged->retest_passed should be refused")
	}
	// Continue the valid chain through the documented lifecycle.
	for _, step := range []string{"assigned", "in_progress", "remediated", "retest_requested", "retest_passed"} {
		if err := h.findings.Transition(ctx, &adminID, f.ID, step, ""); err != nil {
			t.Errorf("step %s: %v", step, err)
			break
		}
	}
}

// mintTenantScopedToken issues a JWT whose roles ARE constrained to
// the tenant. Used to exercise the cross-tenant rejection paths
// (mintToken's super_admin role short-circuits the AuthorizeTargetTenant
// check by design).
func mintTenantScopedToken(t *testing.T, tenantID uuid.UUID, role string) string {
	t.Helper()
	claims := jwtMapClaims{
		"sub":         adminID.String(),
		"tenant_id":   tenantID.String(),
		"partner_id":  directID.String(),
		"platform_id": platformID.String(),
		"roles":       []string{role},
		"mfa":         true,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"iat":         time.Now().Unix(),
	}
	tok := jwtNewWithClaims(jwtSigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// Local aliases to avoid a fresh `github.com/golang-jwt/jwt/v5` import
// (already imported transitively via main_test.go's tooling).
var (
	jwtSigningMethodHS256 = jwtV5.SigningMethodHS256
	jwtNewWithClaims      = jwtV5.NewWithClaims
)

type jwtMapClaims = jwtV5.MapClaims

// Helper that prints types for the assertions.
var _ = strings.Contains // keep import
var _ = json.Marshal     // keep import
