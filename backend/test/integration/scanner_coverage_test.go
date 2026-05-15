//go:build integration

// Coverage regression: every tool registered in scanner_image_registry
// must (a) have a Dockerfile under tools/scanner-images/<tool>/, and
// (b) a parser in parsers.Registry. This test catches the gap I had
// before — 10 tools registered without an image and 7 without a parser
// — and refuses to let it return.

package integration

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zaishield/vaultscan/backend/internal/parsers"
)

func registeredTools(t *testing.T, h *harness) []string {
	t.Helper()
	rows, err := h.pool.Query(context.Background(),
		`SELECT DISTINCT tool FROM scanner_image_registry ORDER BY tool`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tool string
		if err := rows.Scan(&tool); err != nil {
			t.Fatal(err)
		}
		out = append(out, tool)
	}
	return out
}

func TestSCANNERS_EveryRegisteredToolHasDockerfile(t *testing.T) {
	h := newHarness(t)
	tools := registeredTools(t, h)
	if len(tools) < 20 {
		t.Fatalf("expected at least 20 tools in scanner_image_registry, got %d", len(tools))
	}
	_, file, _, _ := runtime.Caller(0)
	// backend/test/integration/<this>.go -> repo root
	repoRoot := filepath.Join(filepath.Dir(file), "..", "..", "..")
	for _, tool := range tools {
		p := filepath.Join(repoRoot, "tools/scanner-images", tool, "Dockerfile")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("tool %q registered but no Dockerfile at %s", tool, p)
		}
	}
}

func TestSCANNERS_EveryRegisteredToolHasParser(t *testing.T) {
	h := newHarness(t)
	tools := registeredTools(t, h)
	for _, tool := range tools {
		if _, ok := parsers.Registry[tool]; !ok {
			t.Errorf("tool %q registered but no parser in parsers.Registry — scanner-worker will skip its output", tool)
		}
	}
}
