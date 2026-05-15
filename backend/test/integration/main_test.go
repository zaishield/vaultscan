//go:build integration

// Integration tests against a live Postgres.
//
// Run: `make integration-test`
// Or:   VAULTSCAN_TEST_DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=disable \
//        go test -tags=integration -count=1 -v ./backend/test/integration/...
//
// The harness:
//   * Picks a fresh search_path schema per test run so reruns don't collide.
//   * Applies every migration in backend/migrations/.
//   * Inserts a deterministic admin user that subsequent tests reference as
//     the actor for created_by FKs.
//   * Exposes the wired services every test uses.
package integration

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/zaishield/vaultscan/backend/internal/agents"
	"github.com/zaishield/vaultscan/backend/internal/assets"
	"github.com/zaishield/vaultscan/backend/internal/audit"
	"github.com/zaishield/vaultscan/backend/internal/authdocs"
	"github.com/zaishield/vaultscan/backend/internal/branding"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/engagements"
	"github.com/zaishield/vaultscan/backend/internal/eventbus"
	"github.com/zaishield/vaultscan/backend/internal/evidence"
	"github.com/zaishield/vaultscan/backend/internal/findings"
	"github.com/zaishield/vaultscan/backend/internal/reporting"
	"github.com/zaishield/vaultscan/backend/internal/scanorch"
	"github.com/zaishield/vaultscan/backend/internal/scopeguard"
	"github.com/zaishield/vaultscan/backend/internal/tenants"
)

// IDs reused across tests so cross-test references stay deterministic.
var (
	platformID = uuid.MustParse("00000000-0000-0000-0000-0000000000a1")
	directID   = uuid.MustParse("00000000-0000-0000-0000-0000000000b1")
	adminID    = uuid.MustParse("00000000-0000-0000-0000-000000000111")
)

type harness struct {
	pool        *pgxpool.Pool
	audit       *audit.Service
	bus         *eventbus.Bus
	branding    *branding.Service
	tenants     *tenants.Service
	engagements *engagements.Service
	authdocs    *authdocs.Service
	assets      *assets.Service
	scope       *scopeguard.Service
	scanorch    *scanorch.Orchestrator
	nodes       *scanorch.NodeOps
	signer      *scanorch.Signer
	agents      *agents.Service
	findings    *findings.Service
	reports     *reporting.Service
	vault       *evidence.Vault
}

var sharedHarness *harness

func TestMain(m *testing.M) {
	dsn := os.Getenv("VAULTSCAN_TEST_DATABASE_URL")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "VAULTSCAN_TEST_DATABASE_URL not set; skipping integration suite")
		os.Exit(0)
	}
	h, cleanup, err := bootHarness(dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "boot harness:", err)
		os.Exit(1)
	}
	sharedHarness = h
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func bootHarness(dsn string) (*harness, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	schema := "it_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]

	// Create the schema via a connection without a custom search_path so the
	// statement runs in the default schema.
	bootPool, err := db.Open(ctx, dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := bootPool.Exec(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %s", schema)); err != nil {
		bootPool.Close()
		return nil, nil, fmt.Errorf("create schema: %w", err)
	}
	// Pre-install extensions in `public` so every test-schema can see them
	// (CREATE EXTENSION is per-database but lives in one schema; without
	// this, an extension installed inside a previous test schema becomes
	// invisible after that schema is dropped).
	for _, ext := range []string{"pgcrypto", "citext"} {
		if _, err := bootPool.Exec(ctx,
			fmt.Sprintf(`CREATE EXTENSION IF NOT EXISTS %s WITH SCHEMA public`, ext)); err != nil {
			bootPool.Close()
			return nil, nil, fmt.Errorf("install extension %s: %w", ext, err)
		}
	}
	bootPool.Close()

	// search_path includes public so the citext / pgcrypto types resolve.
	pool, err := db.Open(ctx, appendOpt(dsn, "search_path", schema+",public"))
	if err != nil {
		return nil, nil, fmt.Errorf("reopen db: %w", err)
	}

	if _, err := pool.Migrate(ctx, findMigrationsDir()); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("migrate: %w", err)
	}

	// Insert a deterministic admin user that subsequent tests reference.
	if _, err := pool.Exec(ctx, `
		INSERT INTO users(id, platform_id, partner_id, email, full_name,
		    mfa_enabled, status)
		VALUES ($1, $2, $3, 'integration-admin@vaultscan.test',
		    'Integration Admin', true, 'active')
		ON CONFLICT (id) DO NOTHING`,
		adminID, platformID, directID); err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("insert admin user: %w", err)
	}

	log := zerolog.New(zerolog.NewConsoleWriter()).Level(zerolog.WarnLevel)
	auditSvc := audit.New(pool.Pool)
	bus := eventbus.New(pool.Pool)
	signer, _ := scanorch.NewSigner("integration-test", "")
	vault, err := evidence.NewVault(pool.Pool, auditSvc, bus,
		"ZGV2LWV2aWRlbmNlLW1hc3Rlci1rZXktY2hhbmdlLW1lLTAwMDAwMDA=")
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("vault: %w", err)
	}
	brand := branding.New(pool.Pool, auditSvc, "zaishield-direct")
	tenSvc := tenants.New(pool.Pool, auditSvc, bus)
	engSvc := engagements.New(pool.Pool, auditSvc, bus)
	docSvc := authdocs.New(pool.Pool, vault, auditSvc, bus)
	assetSvc := assets.New(pool.Pool, auditSvc)
	scope := scopeguard.New(pool.Pool)
	nodeOps, err := scanorch.NewNodeOps(pool.Pool,
		"ZGV2LXNjYW5uZXItcHVsbC1tYXN0ZXIta2V5LTAwMDA=")
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("node ops: %w", err)
	}
	orch := scanorch.New(pool.Pool, scope, auditSvc, bus, signer).WithNodeOps(nodeOps)
	agentSvc := agents.New(pool.Pool, auditSvc, bus)
	findSvc := findings.New(pool.Pool, auditSvc, bus)
	reportSvc := reporting.New(pool.Pool, brand, vault, auditSvc, bus)
	_ = log

	h := &harness{
		pool: pool.Pool, audit: auditSvc, bus: bus, branding: brand,
		tenants: tenSvc, engagements: engSvc, authdocs: docSvc, assets: assetSvc,
		scope: scope, scanorch: orch, nodes: nodeOps, signer: signer,
		agents: agentSvc, findings: findSvc, reports: reportSvc, vault: vault,
	}
	cleanup := func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dropCancel()
		_, _ = pool.Exec(dropCtx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schema))
		pool.Close()
	}
	return h, cleanup, nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	if sharedHarness == nil {
		t.Skip("integration suite not initialised")
	}
	return sharedHarness
}

func findMigrationsDir() string {
	_, file, _, _ := runtime.Caller(0)
	// backend/test/integration/main_test.go -> backend/migrations
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func appendOpt(dsn, key, value string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + key + "=" + value
}

// makeTenant creates a tenant + an active engagement with one approved scope
// target and an authorization document on file. Returns IDs callers use for
// subsequent calls.
func (h *harness) makeTenant(t *testing.T, slug string) (tenantID, engagementID uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	tenant, err := h.tenants.Create(ctx, &adminID, tenants.CreateInput{
		PlatformID: platformID, PartnerID: directID,
		Name: slug, Slug: slug,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	now := time.Now().UTC()
	eng, err := h.engagements.Create(ctx, &adminID, engagements.CreateInput{
		PlatformID: platformID, PartnerID: directID, TenantID: tenant.ID,
		Code: "ENG-" + slug, Name: slug + " engagement",
		StartsAt: now.Add(-time.Hour), EndsAt: now.Add(30 * 24 * time.Hour),
		Intensity: "standard",
	})
	if err != nil {
		t.Fatalf("create engagement: %v", err)
	}

	if _, err := h.authdocs.Upload(ctx, &adminID, authdocs.UploadInput{
		EngagementID: eng.ID, Title: "Test Auth", DocumentType: "letter",
		Body:        strings.NewReader("AUTHORIZATION (TEST)"),
		ContentType: "text/plain", SignedBy: "Test",
	}); err != nil {
		t.Fatalf("upload auth doc: %v", err)
	}

	return tenant.ID, eng.ID
}
