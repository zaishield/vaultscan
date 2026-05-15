// Package logging provides a process-wide structured logger.
package logging

import (
	"os"
	"strings"
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
