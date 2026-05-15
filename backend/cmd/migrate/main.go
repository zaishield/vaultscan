// migrate is the schema migration runner.
package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/zaishield/vaultscan/backend/internal/config"
	"github.com/zaishield/vaultscan/backend/internal/db"
	"github.com/zaishield/vaultscan/backend/internal/logging"
)

func main() {
	dir := flag.String("dir", "backend/migrations", "migrations directory")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log := logging.New(cfg.Env)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("open db")
	}
	defer conn.Close()

	applied, err := conn.Migrate(ctx, *dir)
	if err != nil {
		log.Fatal().Err(err).Msg("migrate")
	}
	if len(applied) == 0 {
		log.Info().Msg("schema up to date")
		os.Exit(0)
	}
	for _, v := range applied {
		log.Info().Str("version", v).Msg("applied migration")
	}
}
