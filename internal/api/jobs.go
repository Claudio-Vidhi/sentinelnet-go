package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/driver"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// Job: unità di lavoro asincrona (triage globale, bulk-command, scan-subnet).
type Job struct {
	ID       string           `json:"job_id"`
	Status   string           `json:"status"`   // running | done | error
	Progress int              `json:"progress"` // elementi completati
	Total    int              `json:"total"`
	Results  []map[string]any `json:"results"`
}

// TriageStatus: stato globale mostrato dalla progress bar del triage.
type TriageStatus struct {
	Status        string `json:"status"` // running | idle
	Total         int    `json:"total"`
	Progress      int    `json:"progress"`
	CurrentDevice string `json:"current_device"`
}

func newJobID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a *App) newJob(total int) *Job {
	j := &Job{ID: newJobID(), Status: "running", Total: total, Results: []map[string]any{}}
	a.jobsMu.Lock()
	a.jobs[j.ID] = j
	a.jobsMu.Unlock()
	return j
}

func (a *App) getJob(id string) *Job {
	a.jobsMu.Lock()
	defer a.jobsMu.Unlock()
	return a.jobs[id]
}

func (a *App) updateJob(id string, fn func(*Job)) {
	a.jobsMu.Lock()
	defer a.jobsMu.Unlock()
	if j := a.jobs[id]; j != nil {
		fn(j)
	}
}

// resolveCreds: credenziali dedicate del device (decifrate) oppure il profilo
// standard dalla configurazione (profile=default).
func (a *App) resolveCreds(d *store.Device) collect.Credentials {
	if d.Profile == "default" || d.Username == "" {
		return collect.Credentials{
			Username:     a.cfg.DefaultUser,
			Password:     a.cfg.DefaultPass,
			EnableSecret: a.cfg.DefaultSecret,
		}
	}
	pass, _ := a.vault.Decrypt(d.PasswordEnc)
	sec, _ := a.vault.Decrypt(d.EnableSecretEnc)
	return collect.Credentials{Username: d.Username, Password: pass, EnableSecret: sec}
}

// driverFor risolve il driver CLI di un vendor: prima il campo 'driver' del
// registro vendor, poi il fallback per nome vendor (come resolve_driver del Python).
func (a *App) driverFor(vendor string) driver.Driver {
	drvName := ""
	if vendors, err := a.store.ListVendors(); err == nil {
		if m, ok := vendors[strings.ToLower(strings.TrimSpace(vendor))]; ok {
			drvName = m.Driver
		}
	}
	return driver.ResolveOrDefault(vendor, drvName)
}

// triageDevice esegue backup+triage su un device, persistendo versione,
// backup config e dati di topologia. Ritorna il risultato collect.
func (a *App) triageDevice(ctx context.Context, d *store.Device) collect.TriageResult {
	res := collect.RunBackupAndTriage(ctx, d.IP, a.resolveCreds(d), a.driverFor(d.Vendor))
	if res.Status != "success" {
		_ = a.store.SetVersionStatus(d.IP, "offline")
		return res
	}
	_ = a.store.UpsertVersion(d.IP, d.Vendor, res.Version, "online")
	if res.Hostname != "" {
		_ = a.store.SetDeviceHostname(d.IP, res.Hostname)
	}
	a.persistTopology(d, res)
	a.saveBackup(d, res.Config)
	return res
}

var _ = time.Now
