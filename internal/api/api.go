// Package api: router HTTP, middleware (auth/RBAC/tenant scoping) e handler,
// con contratti JSON identici all'app FastAPI cosi la dashboard gira invariata.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/pingmon"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

type App struct {
	cfg   *config.Config
	store *store.Store
	auth  *auth.Service
	vault *crypto.Vault

	// Pipeline di osservabilita. Opzionale.
	obs    *obsstore.Store
	obsMgr *observability.Manager

	// Monitor ping continuo inventario.
	pingMon *pingmon.Monitor

	// Job asincroni (triage / bulk-command / scan-subnet).
	jobsMu sync.Mutex
	jobs   map[string]*Job

	// Stato del triage globale in background (per la progress bar).
	triageMu     sync.Mutex
	triageStatus TriageStatus

	// Ciclo di vita legato all'interfaccia.
	lastBeat     atomic.Int64
	autoShutdown atomic.Bool
	onShutdown   func()
	shutdownOnce sync.Once
}

func NewApp(cfg *config.Config, st *store.Store, authSvc *auth.Service, vault *crypto.Vault) *App {
	app := &App{
		cfg:   cfg,
		store: st,
		auth:  authSvc,
		vault: vault,
		jobs:  map[string]*Job{},
	}
	app.pingMon = pingmon.New(st, app.auditLog)
	return app
}

// EnableObservability collega la pipeline di osservabilita e ne ritorna il manager.
func (a *App) EnableObservability(obs *obsstore.Store) *observability.Manager {
	mgr := observability.NewManager(obs, a.store, a.auditLog)
	mgr.SetClientFunc(a.fgtClient)
	a.obs, a.obsMgr = obs, mgr
	return mgr
}

// ---- context: claims dell'utente autenticato ----

type ctxKey int

const claimsKey ctxKey = iota

func claimsFrom(ctx context.Context) *auth.Claims {
	c, _ := ctx.Value(claimsKey).(*auth.Claims)
	return c
}

// ---- helper risposta ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Errori nello stile FastAPI: {"detail": "..."}.
func writeErr(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 8<<20))
	return dec.Decode(dst)
}

// tenantsForUser: sedi visibili dell'utente (nil = tutte). Gli admin vedono tutto.
func (a *App) tenantsForUser(username, role string) ([]string, error) {
	if role == "admin" {
		return nil, nil
	}
	ts, err := a.store.UserTenants(username)
	if err != nil {
		return nil, err
	}
	if len(ts) == 0 {
		return nil, nil // nessuna restrizione = tutte
	}
	return ts, nil
}

func canSeeTenant(scoped []string, tenant string) bool {
	if scoped == nil {
		return true
	}
	for _, t := range scoped {
		if t == tenant {
			return true
		}
	}
	return false
}
