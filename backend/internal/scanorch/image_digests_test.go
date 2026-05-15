package scanorch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDigestsFile(t *testing.T, dir, version, registry string, digests map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "digests.json")
	body, _ := json.Marshal(map[string]any{
		"version": version, "registry": registry, "digests": digests,
	})
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRegistry_LoadsAndPinsImage(t *testing.T) {
	path := writeDigestsFile(t, t.TempDir(), "v1.4.0",
		"ghcr.io/zaishield/vaultscan/scanners",
		map[string]string{
			"nmap":   "sha256:aaa111",
			"nuclei": "sha256:bbb222",
		})
	reg, err := NewImageDigestRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	got := reg.ImageRefFor("nmap", "fallback")
	want := "ghcr.io/zaishield/vaultscan/scanners/nmap@sha256:aaa111"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
	if reg.Version() != "v1.4.0" {
		t.Errorf("Version() = %s", reg.Version())
	}
	if !reg.IsPinned("nmap") {
		t.Error("nmap should be pinned")
	}
}

func TestRegistry_FallbackToLatestWhenUnpinned(t *testing.T) {
	path := writeDigestsFile(t, t.TempDir(), "v1.4.0",
		"ghcr.io/zaishield/vaultscan/scanners",
		map[string]string{"nmap": "sha256:aaa"})
	reg, _ := NewImageDigestRegistry(path)
	got := reg.ImageRefFor("zap", "fallback")
	if !strings.Contains(got, ":latest") {
		t.Errorf("unpinned tool should fall back to :latest; got %s", got)
	}
}

func TestRegistry_MissingFileReturnsEmptyRegistry(t *testing.T) {
	reg, err := NewImageDigestRegistry("/nonexistent/path/digests.json")
	if err != nil {
		t.Fatalf("missing file should not error; got %v", err)
	}
	if reg.IsPinned("anything") {
		t.Error("empty registry should not claim to be pinned")
	}
	got := reg.ImageRefFor("nmap", "fallback")
	if got != "fallback/nmap:latest" {
		t.Errorf("got %s", got)
	}
}

func TestRegistry_StrictModeErrorsOnMiss(t *testing.T) {
	path := writeDigestsFile(t, t.TempDir(), "v1", "registry",
		map[string]string{"nmap": "sha256:x"})
	reg, _ := NewImageDigestRegistry(path)
	if _, err := reg.ImageRefForStrict("nuclei", "fallback"); !errors.Is(err, ErrNoDigest) {
		t.Errorf("expected ErrNoDigest, got %v", err)
	}
	ref, err := reg.ImageRefForStrict("nmap", "fallback")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "registry/nmap@sha256:x" {
		t.Errorf("got %s", ref)
	}
}

func TestRegistry_AllReturnsCopy(t *testing.T) {
	path := writeDigestsFile(t, t.TempDir(), "v1", "reg",
		map[string]string{"nmap": "sha256:x"})
	reg, _ := NewImageDigestRegistry(path)
	m := reg.All()
	m["nmap"] = "TAMPERED"
	// Internal state must not be affected.
	if reg.ImageRefFor("nmap", "f") != "reg/nmap@sha256:x" {
		t.Error("All() must return a copy, not the live map")
	}
}

func TestRegistry_InvalidJSONIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "digests.json")
	_ = os.WriteFile(path, []byte("not json"), 0o600)
	if _, err := NewImageDigestRegistry(path); err == nil {
		t.Error("invalid JSON should error")
	}
}
