package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// Logging is the spine of every observability signal: every audit hash,
// every rate-limit decision, every panic recovery has to land in
// structured JSON with a stable shape. Even a 20-line wrapper deserves
// a contract test so a stray refactor can't silently change the field
// names that downstream Loki / Splunk parsers depend on.

func TestNew_DefaultLevelInfo(t *testing.T) {
	t.Setenv("VAULTSCAN_LOG_LEVEL", "")
	l := New("production")
	if got, want := l.GetLevel(), zerolog.InfoLevel; got != want {
		t.Errorf("default level=%v want %v", got, want)
	}
}

func TestNew_DevelopmentEnvImpliesDebug(t *testing.T) {
	t.Setenv("VAULTSCAN_LOG_LEVEL", "")
	l := New("development")
	if l.GetLevel() != zerolog.DebugLevel {
		t.Errorf("development env should be Debug; got %v", l.GetLevel())
	}
}

func TestNew_VAULTSCANLogLevelOverridesEnv(t *testing.T) {
	t.Setenv("VAULTSCAN_LOG_LEVEL", "debug")
	l := New("production")
	if l.GetLevel() != zerolog.DebugLevel {
		t.Errorf("VAULTSCAN_LOG_LEVEL=debug should force Debug; got %v", l.GetLevel())
	}
	// case-insensitive
	t.Setenv("VAULTSCAN_LOG_LEVEL", "DEBUG")
	l2 := New("production")
	if l2.GetLevel() != zerolog.DebugLevel {
		t.Errorf("VAULTSCAN_LOG_LEVEL=DEBUG (case-insensitive) should force Debug; got %v", l2.GetLevel())
	}
}

func TestNew_EmitsServiceAndEnvFields(t *testing.T) {
	t.Setenv("VAULTSCAN_LOG_LEVEL", "")
	var buf bytes.Buffer
	base := New("production")
	l := base.Output(&buf)
	l.Info().Str("hello", "world").Msg("ping")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("log line not valid JSON: %v\n%s", err, buf.String())
	}
	if got["service"] != "vaultscan" {
		t.Errorf(`service=%v want "vaultscan"`, got["service"])
	}
	if got["env"] != "production" {
		t.Errorf(`env=%v want "production"`, got["env"])
	}
	if got["hello"] != "world" {
		t.Errorf(`hello=%v want "world"`, got["hello"])
	}
	if got["message"] != "ping" {
		t.Errorf(`message=%v want "ping"`, got["message"])
	}
	// timestamp is RFC3339Nano — fail if it's missing or obviously wrong.
	ts, _ := got["time"].(string)
	if !strings.Contains(ts, "T") || !(strings.HasSuffix(ts, "Z") || strings.Contains(ts, "+") || strings.Contains(ts, "-")) {
		t.Errorf("time=%q does not look like RFC3339Nano", ts)
	}
}

func TestNew_ProductionInfoSuppressesDebug(t *testing.T) {
	t.Setenv("VAULTSCAN_LOG_LEVEL", "")
	var buf bytes.Buffer
	l := New("production").Output(&buf)
	l.Debug().Msg("should-not-appear")
	if buf.Len() != 0 {
		t.Errorf("debug log leaked at info level: %s", buf.String())
	}
}
