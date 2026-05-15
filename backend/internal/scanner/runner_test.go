package scanner

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestNewRunner_DefaultByEnv(t *testing.T) {
	cases := map[string]bool{
		"":            true,
		"development": true,
		"staging":     true,
		"production":  false,
		"PRODUCTION":  false,
		"prod":        false,
		"  prod  ":    false,
	}
	for env, wantAllow := range cases {
		t.Run("env="+env, func(t *testing.T) {
			t.Setenv("VAULTSCAN_ENV", env)
			r := NewRunner()
			if r.AllowSynthetic != wantAllow {
				t.Errorf("AllowSynthetic=%v, want %v", r.AllowSynthetic, wantAllow)
			}
		})
	}
}

func TestRunner_RefusesSyntheticInProductionMode(t *testing.T) {
	r := NewRunnerStrict()
	if r.AllowSynthetic {
		t.Fatal("strict runner shouldn't allow synthetic")
	}
	// Use a tool name that definitely isn't on PATH.
	_, err := r.Run(context.Background(), "vaultscan-nonexistent-tool", []string{"127.0.0.1"}, time.Second)
	if !errors.Is(err, ErrSyntheticForbidden) {
		t.Fatalf("expected ErrSyntheticForbidden, got %v", err)
	}
}

func TestRunner_AllowsSyntheticInTestMode(t *testing.T) {
	r := NewRunnerForTest()
	if !r.AllowSynthetic {
		t.Fatal("test runner should allow synthetic")
	}
	res, err := r.Run(context.Background(), "vaultscan-nonexistent-tool", []string{"127.0.0.1"}, time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Synthetic {
		t.Error("expected Synthetic=true")
	}
	if len(res.Output) == 0 {
		t.Error("expected non-empty synthetic output")
	}
}

func TestRunner_NewRunner_RespectsRuntimeEnvFlip(t *testing.T) {
	// First boot in dev — allow.
	t.Setenv("VAULTSCAN_ENV", "development")
	devR := NewRunner()
	if !devR.AllowSynthetic {
		t.Fatal("dev runner should allow synthetic")
	}
	// New boot in prod — disallow. (Same process, simulates reload.)
	t.Setenv("VAULTSCAN_ENV", "production")
	prodR := NewRunner()
	if prodR.AllowSynthetic {
		t.Fatal("prod runner should disallow synthetic")
	}
}

func TestRunner_StrictModeFromEnv(t *testing.T) {
	// Using NewRunner() in production env should produce a strict runner.
	t.Setenv("VAULTSCAN_ENV", "production")
	r := NewRunner()
	_, err := r.Run(context.Background(), "vaultscan-definitely-missing-binary", []string{"x"}, time.Second)
	if !errors.Is(err, ErrSyntheticForbidden) {
		t.Fatalf("prod NewRunner should refuse synthetic; got %v", err)
	}
	// Sanity: clear env, default re-allows.
	_ = os.Unsetenv("VAULTSCAN_ENV")
	r2 := NewRunner()
	if !r2.AllowSynthetic {
		t.Error("env unset should default to AllowSynthetic=true (dev)")
	}
}
