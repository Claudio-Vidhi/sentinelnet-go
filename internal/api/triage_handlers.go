package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/topology"
	"github.com/go-chi/chi/v5"
	"golang.org/x/sync/errgroup"
)

const triageConcurrency = 8

var reVTPStatusDomain = regexp.MustCompile(`(?im)^\s*VTP Domain Name\s*:\s*(\S+)`)
var reVTPStatusMode = regexp.MustCompile(`(?im)^\s*VTP Operating Mode\s*:\s*(\S+)`)

// persistTopology estrae e salva neighbor CDP/LLDP, port-channel e VTP.
func (a *App) persistTopology(d *store.Device, res collect.TriageResult) {
	dt := topology.ParseConfig(res.Config)
	hostname := res.Hostname
	if hostname == "" {
		hostname = dt.Hostname
	}
	if hostname == "" {
		hostname = d.Hostname
	}
	// VTP: preferisci "show vtp status" alla config.
	vtpDomain, vtpMode := dt.VTPDomain, dt.VTPMode
	if m := reVTPStatusDomain.FindStringSubmatch(res.VTPStatus); len(m) == 2 {
		vtpDomain = m[1]
	}
	if m := reVTPStatusMode.FindStringSubmatch(res.VTPStatus); len(m) == 2 {
		vtpMode = strings.ToLower(m[1])
	}

	neighbors := topology.ParseCDPNeighbors(hostname, res.CDPOutput)
	neighbors = append(neighbors, topology.ParseLLDPNeighbors(hostname, res.LLDPOutput)...)
	_ = a.store.UpsertTopology(d.IP, hostname, vtpDomain, vtpMode, neighbors, dt.PortChannels)
}

// saveBackup scrive la running-config su file backup-config/<tenant>/<host>-<ip>.txt.
func (a *App) saveBackup(d *store.Device, cfg string) {
	if strings.TrimSpace(cfg) == "" {
		return
	}
	dir := filepath.Join(a.cfg.BackupDir(), sanitizeFile(d.Tenant))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	host := d.Hostname
	if host == "" {
		host = "device"
	}
	name := fmt.Sprintf("%s-%s.txt", sanitizeFile(host), d.IP)
	_ = os.WriteFile(filepath.Join(dir, name), []byte(cfg), 0o644)
}

func sanitizeFile(s string) string {
	s = strings.TrimSpace(s)
	return regexp.MustCompile(`[^\w.\-]+`).ReplaceAllString(s, "_")
}

type runTriageReq struct {
	Group string `json:"group"`
}

func (a *App) handleRunTriage(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	var req runTriageReq
	_ = decodeJSON(r, &req)

	// Evita triage concorrenti globali.
	a.triageMu.Lock()
	if a.triageStatus.Status == "running" {
		a.triageMu.Unlock()
		writeErr(w, http.StatusConflict, "un triage è già in corso")
		return
	}
	a.triageMu.Unlock()

	devices, err := a.store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var targets []*store.Device
	for _, d := range devices {
		if !canSeeTenant(scoped, d.Tenant) {
			continue
		}
		if req.Group != "" && req.Group != "all" && d.Tenant != req.Group {
			continue
		}
		targets = append(targets, d)
	}
	if len(targets) == 0 {
		writeErr(w, http.StatusBadRequest, "nessun dispositivo nel perimetro selezionato")
		return
	}

	a.triageMu.Lock()
	a.triageStatus = TriageStatus{Status: "running", Total: len(targets), Progress: 0}
	a.triageMu.Unlock()

	go a.runTriageBatch(targets)
	writeJSON(w, http.StatusOK, map[string]any{"status": "started", "total": len(targets)})
}

func (a *App) runTriageBatch(targets []*store.Device) {
	ctx := context.Background()
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(triageConcurrency)
	for _, d := range targets {
		d := d
		g.Go(func() error {
			dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			a.triageMu.Lock()
			a.triageStatus.CurrentDevice = d.IP
			a.triageMu.Unlock()

			a.triageDevice(dctx, d)

			a.triageMu.Lock()
			a.triageStatus.Progress++
			a.triageMu.Unlock()
			return nil
		})
	}
	_ = g.Wait()
	a.triageMu.Lock()
	a.triageStatus.Status = "idle"
	a.triageMu.Unlock()
}

func (a *App) handleTriageStatus(w http.ResponseWriter, _ *http.Request) {
	a.triageMu.Lock()
	st := a.triageStatus
	a.triageMu.Unlock()
	if st.Status == "" {
		st.Status = "idle"
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *App) handleTriageOne(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !a.deviceIPInScope(w, r, ip) {
		return
	}
	d, err := a.store.GetDevice(ip)
	if err != nil || d == nil {
		writeErr(w, http.StatusNotFound, "dispositivo non trovato")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res := a.triageDevice(ctx, d)
	if res.Status != "success" {
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "message": res.Message})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"version":  res.Version,
		"hostname": res.Hostname,
	})
}

// ---- Ping ----

type pingReq struct {
	Group string `json:"group"`
}

func (a *App) handlePingCheck(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	var req pingReq
	_ = decodeJSON(r, &req)
	devices, err := a.store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var targets []*store.Device
	for _, d := range devices {
		if !canSeeTenant(scoped, d.Tenant) {
			continue
		}
		if req.Group != "" && req.Group != "all" && d.Tenant != req.Group {
			continue
		}
		targets = append(targets, d)
	}

	results := map[string]bool{}
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(r.Context())
	g.SetLimit(16)
	for _, d := range targets {
		d := d
		g.Go(func() error {
			alive := collect.Ping(ctx, d.IP)
			mu.Lock()
			results[d.IP] = alive
			mu.Unlock()
			status := "offline"
			if alive {
				status = "online"
			}
			_ = a.store.SetVersionStatus(d.IP, status)
			return nil
		})
	}
	_ = g.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *App) handlePingOne(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !a.deviceIPInScope(w, r, ip) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	alive := collect.Ping(ctx, ip)
	status := "offline"
	if alive {
		status = "online"
	}
	_ = a.store.SetVersionStatus(ip, status)
	writeJSON(w, http.StatusOK, map[string]any{"reachable": alive})
}

// ---- Backup download ----

func (a *App) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	// Cerca il file di backup per IP o per nome file, prevenendo path traversal.
	path, filename := a.findBackup(name)
	if path == "" {
		writeErr(w, http.StatusNotFound, "backup non trovato")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "backup non leggibile")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(data)
}

// findBackup risolve un IP o un nome file a un percorso sicuro dentro BackupDir.
func (a *App) findBackup(name string) (string, string) {
	base := a.cfg.BackupDir()
	cleanName := filepath.Base(name) // neutralizza ../
	var found, foundName string
	_ = filepath.Walk(base, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		fn := info.Name()
		if fn == cleanName || strings.Contains(fn, "-"+cleanName+".txt") || strings.HasSuffix(fn, cleanName+".txt") {
			found, foundName = p, fn
			return filepath.SkipAll
		}
		return nil
	})
	return found, foundName
}
