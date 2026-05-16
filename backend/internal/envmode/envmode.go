// Package envmode is the one place that answers "are we in production?".
//
// Prior to this package three near-identical helpers existed:
//   cmd/agent-gateway/main.go         isProductionEnv(env string) bool
//   internal/config/production_guard  (*Config).isProductionMode() bool
//   internal/scanner/runner.go        isProductionEnv() bool (reads env)
//
// Same logic, three places to keep in sync. This package owns the
// canonical predicate; callers depend on it.
//
// Recognised values (case-insensitive, whitespace-trimmed):
//   "production", "prod"   → true
//   anything else / empty  → false
package envmode

import (
	"os"
	"strings"
)

// IsProduction reports whether v names the production environment.
// Pure function so it's trivially testable.
func IsProduction(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "production" || v == "prod"
}

// FromEnv reads VAULTSCAN_ENV and applies IsProduction. Convenience
// for the common case.
func FromEnv() bool { return IsProduction(os.Getenv("VAULTSCAN_ENV")) }
