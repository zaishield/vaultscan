// Package logging provides a process-wide structured logger.
package logging

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

func New(env string) zerolog.Logger {
	level := zerolog.InfoLevel
	if strings.EqualFold(os.Getenv("VAULTSCAN_LOG_LEVEL"), "debug") || env == "development" {
		level = zerolog.DebugLevel
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano
	return zerolog.New(os.Stderr).Level(level).With().
		Timestamp().Str("service", "vaultscan").Str("env", env).Logger()
}

// componentLogger lazy-initialises a process-wide logger that
// component packages (evidence, audit, cron-runner workers) can
// share — closing the previous gap where each component constructed
// its own zerolog.New(os.Stderr) call, bypassing the central level
// + service-name + env labelling set up by New().
//
// First call to Component() during process startup latches the
// underlying zerolog.Logger; subsequent calls reuse it. main()
// SHOULD call SetDefault(l) right after constructing its logger so
// the global is wired with the right env + level; otherwise the
// first Component() call falls back to a sensible default.
var (
	defaultMu     sync.RWMutex
	defaultLogger *zerolog.Logger
)

// SetDefault registers l as the process-wide logger that subsequent
// Component() calls derive from. Safe to call multiple times; the
// last call wins. main() should invoke this immediately after
// logging.New(cfg.Env).
func SetDefault(l zerolog.Logger) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultLogger = &l
}

// Component returns a child logger with a `component=<name>` label.
// Use this in package-level loggers instead of zerolog.New(os.Stderr)
// so the central level/env/service plumbing flows through.
func Component(name string) zerolog.Logger {
	defaultMu.RLock()
	d := defaultLogger
	defaultMu.RUnlock()
	if d == nil {
		// Fallback for callers that fired before main() called
		// SetDefault. Mirrors New("")'s output shape so log scrapers
		// keyed on the labels keep working.
		fallback := zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().
			Timestamp().Str("service", "vaultscan").Str("component", name).Logger()
		return fallback
	}
	return d.With().Str("component", name).Logger()
}
