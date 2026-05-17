package db

import (
	"os"
	"testing"
	"time"
)

// db is a thin wrapper over pgxpool; the connection-pool logic itself
// is upstream-tested. The two pieces *we* own are the env-var parsing
// for pool tuning + DefaultPoolConfig's sane fallbacks. Both are
// pure functions safe to unit-test.

func TestDefaultPoolConfig_Defaults(t *testing.T) {
	// Cannot run in parallel — uses Setenv to clear env vars.
	for _, k := range []string{
		"VAULTSCAN_PG_MAX_CONNS", "VAULTSCAN_PG_MIN_CONNS",
		"VAULTSCAN_PG_MAX_CONN_LIFETIME", "VAULTSCAN_PG_MAX_CONN_IDLE",
		"VAULTSCAN_PG_HEALTHCHECK",
	} {
		t.Setenv(k, "")
		// Setenv with "" sets it to empty (not unset), and envInt32 /
		// envDur treat empty as "use default".
		os.Unsetenv(k)
	}
	cfg := DefaultPoolConfig()
	if cfg.MaxConns != 32 {
		t.Errorf("MaxConns=%d want 32", cfg.MaxConns)
	}
	if cfg.MinConns != 4 {
		t.Errorf("MinConns=%d want 4", cfg.MinConns)
	}
	if cfg.MaxConnLifetime != time.Hour {
		t.Errorf("MaxConnLifetime=%v want 1h", cfg.MaxConnLifetime)
	}
	if cfg.MaxConnIdle != 30*time.Minute {
		t.Errorf("MaxConnIdle=%v want 30m", cfg.MaxConnIdle)
	}
	if cfg.HealthCheck != time.Minute {
		t.Errorf("HealthCheck=%v want 1m", cfg.HealthCheck)
	}
}

func TestDefaultPoolConfig_RespectsEnvOverrides(t *testing.T) {
	t.Setenv("VAULTSCAN_PG_MAX_CONNS", "128")
	t.Setenv("VAULTSCAN_PG_MIN_CONNS", "16")
	t.Setenv("VAULTSCAN_PG_MAX_CONN_LIFETIME", "2h")
	t.Setenv("VAULTSCAN_PG_HEALTHCHECK", "30s")

	cfg := DefaultPoolConfig()
	if cfg.MaxConns != 128 {
		t.Errorf("MaxConns=%d want 128", cfg.MaxConns)
	}
	if cfg.MinConns != 16 {
		t.Errorf("MinConns=%d want 16", cfg.MinConns)
	}
	if cfg.MaxConnLifetime != 2*time.Hour {
		t.Errorf("MaxConnLifetime=%v want 2h", cfg.MaxConnLifetime)
	}
	if cfg.HealthCheck != 30*time.Second {
		t.Errorf("HealthCheck=%v want 30s", cfg.HealthCheck)
	}
}

func TestEnvInt32_RejectsNegativeAndGarbage(t *testing.T) {
	t.Setenv("__TEST_INT", "garbage")
	if got := envInt32("__TEST_INT", 42); got != 42 {
		t.Errorf("garbage → %d want default 42", got)
	}
	t.Setenv("__TEST_INT", "-5")
	if got := envInt32("__TEST_INT", 42); got != 42 {
		t.Errorf("negative → %d want default 42 (envInt32 rejects ≤0)", got)
	}
	t.Setenv("__TEST_INT", "7")
	if got := envInt32("__TEST_INT", 42); got != 7 {
		t.Errorf("valid → %d want 7", got)
	}
}

func TestPoolConfigForComponent_Defaults(t *testing.T) {
	t.Setenv("VAULTSCAN_PG_MAX_CONNS_API", "")
	// Per-component defaults: api larger than cron-runner.
	api := PoolConfigForComponent("api")
	cron := PoolConfigForComponent("cron-runner")
	if api.MaxConns <= cron.MaxConns {
		t.Errorf("api MaxConns=%d should exceed cron-runner MaxConns=%d",
			api.MaxConns, cron.MaxConns)
	}
}

func TestPoolConfigForComponent_RespectsGlobalEnvOverride(t *testing.T) {
	// The global VAULTSCAN_PG_MAX_CONNS overrides the component default.
	t.Setenv("VAULTSCAN_PG_MAX_CONNS", "256")
	api := PoolConfigForComponent("api")
	if api.MaxConns != 256 {
		t.Errorf("global override ignored, got MaxConns=%d", api.MaxConns)
	}
}

func TestPoolConfigForComponent_UnknownFallsBackToDefault(t *testing.T) {
	api := PoolConfigForComponent("api")
	unknown := PoolConfigForComponent("never-heard-of-this-component")
	def := DefaultPoolConfig()
	if unknown.MaxConns != def.MaxConns {
		t.Errorf("unknown component should use DefaultPoolConfig, got %d want %d",
			unknown.MaxConns, def.MaxConns)
	}
	_ = api
}

func TestOpenReplica_EmptyDSNReturnsNil(t *testing.T) {
	// Empty DSN must produce nil + nil error so callers can no-op.
	rp, err := OpenReplica(t.Context(), "")
	if err != nil {
		t.Fatalf("err=%v want nil", err)
	}
	if rp != nil {
		t.Fatalf("rp=%v want nil", rp)
	}
}

func TestReader_FallsBackToPrimaryWhenReplicaNil(t *testing.T) {
	// Reader(primary, nil) must equal primary.
	// We use a sentinel by constructing a pgxpool.Pool stub — but we
	// can't easily construct a real one without a DB, so this test
	// asserts the typed-nil branch.
	got := Reader(nil, nil)
	if got != nil {
		t.Errorf("Reader(nil, nil) = %v want nil", got)
	}
}

func TestEnvDur_RejectsBadDurations(t *testing.T) {
	t.Setenv("__TEST_DUR", "not-a-duration")
	if got := envDur("__TEST_DUR", 5*time.Second); got != 5*time.Second {
		t.Errorf("bad → %v want 5s default", got)
	}
	t.Setenv("__TEST_DUR", "10m")
	if got := envDur("__TEST_DUR", 5*time.Second); got != 10*time.Minute {
		t.Errorf("valid → %v want 10m", got)
	}
	t.Setenv("__TEST_DUR", "0s")
	if got := envDur("__TEST_DUR", 5*time.Second); got != 5*time.Second {
		t.Errorf("zero duration should fall back, got %v", got)
	}
}
