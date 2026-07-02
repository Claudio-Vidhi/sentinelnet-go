// Command sentinelnet: server HTTP di SentinelNet (port Go dell'app FastAPI).
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/api"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		logger.Error("creazione data dir fallita", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DBPath())
	if err != nil {
		logger.Error("apertura DB fallita", "err", err)
		os.Exit(1)
	}
	defer st.DB.Close()

	masterKey, err := crypto.LoadKey(cfg.MasterKeyPath())
	if err != nil {
		logger.Error("master key non disponibile", "err", err)
		os.Exit(1)
	}
	vault, err := crypto.NewVault(masterKey)
	if err != nil {
		logger.Error("inizializzazione vault fallita", "err", err)
		os.Exit(1)
	}

	jwtSecret, err := auth.LoadJWTSecret(cfg.JWTSecret, cfg.JWTKeyPath())
	if err != nil {
		logger.Error("JWT secret non disponibile", "err", err)
		os.Exit(1)
	}
	authSvc := auth.New(jwtSecret)

	app := api.NewApp(cfg, st, authSvc, vault)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("SentinelNet in ascolto", "addr", cfg.Addr, "data_dir", cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server terminato con errore", "err", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown su SIGINT/SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	logger.Info("arresto in corso...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
