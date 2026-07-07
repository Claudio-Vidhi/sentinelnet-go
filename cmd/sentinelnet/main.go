// Command sentinelnet: server HTTP di SentinelNet (port Go dell'app FastAPI).
package main

import (
	"context"
	"flag"
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
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ui"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Modalità interfaccia: -ui app|browser|none|ask (default: env SENTINELNET_UI o "ask").
	uiFlag := flag.String("ui", os.Getenv("SENTINELNET_UI"),
		"interfaccia all'avvio: app (finestra dedicata) | browser | none | ask")
	flag.Parse()

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

	// Precedenza indirizzo di ascolto: SENTINELNET_ADDR (host:porta completo) >
	// SENTINELNET_HOST (solo host, porta di default) > host persistito > default.
	addr := cfg.Addr
	if os.Getenv("SENTINELNET_ADDR") == "" {
		addr = app.ResolveListenAddr()
	}
	cfg.Addr = addr

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           app.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Arresto scatenato dalla chiusura dell'interfaccia (libera la porta).
	uiClosed := make(chan struct{})
	app.SetOnShutdown(func() { close(uiClosed) })

	go func() {
		logger.Info("SentinelNet in ascolto", "addr", cfg.Addr, "data_dir", cfg.DataDir)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server terminato con errore", "err", err)
			os.Exit(1)
		}
	}()

	// Apertura dell'interfaccia (finestra app o browser) secondo la scelta.
	url := browseURL(cfg.Addr)
	mode := ui.Resolve(ui.Mode(chooseMode(*uiFlag)), url)
	cmd, err := ui.Launch(mode, cfg.Addr, url)
	if err != nil {
		logger.Warn("apertura interfaccia non riuscita", "err", err, "url", url)
	} else if mode == ui.ModeNone {
		logger.Info("interfaccia non aperta automaticamente", "url", url)
	}

	// Con interfaccia attiva, il server si arresta alla sua chiusura:
	//  - modalità app: quando la finestra dedicata (processo) esce;
	//  - qualsiasi modalità: quando cessano gli heartbeat dalla pagina.
	if mode != ui.ModeNone {
		app.EnableAutoShutdown()
		go app.MonitorLiveness(8 * time.Second)
		if cmd != nil {
			go func() {
				_ = cmd.Wait()
				logger.Info("finestra app chiusa")
				app.TriggerShutdown()
			}()
		}
	}

	// Graceful shutdown su SIGINT/SIGTERM oppure alla chiusura dell'interfaccia.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-stop:
		logger.Info("segnale di arresto ricevuto")
	case <-uiClosed:
		logger.Info("interfaccia chiusa: arresto server e rilascio porta")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// chooseMode normalizza il valore del flag/env; vuoto → "ask".
func chooseMode(v string) string {
	if v == "" {
		return "ask"
	}
	return v
}

// browseURL costruisce l'URL raggiungibile dal browser a partire dall'addr di ascolto.
func browseURL(addr string) string {
	if len(addr) > 0 && addr[0] == ':' {
		return "http://localhost" + addr
	}
	return "http://" + addr
}
