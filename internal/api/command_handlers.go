package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
	"golang.org/x/sync/errgroup"
)

func (a *App) handleJobStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "job_id")
	j := a.getJob(id)
	if j == nil {
		writeErr(w, http.StatusNotFound, "job non trovato")
		return
	}
	a.jobsMu.Lock()
	defer a.jobsMu.Unlock()
	writeJSON(w, http.StatusOK, j)
}

type bulkReq struct {
	IPs      []string `json:"ips"`
	Commands string   `json:"commands"`
	Mode     string   `json:"mode"` // exec | config
	Save     bool     `json:"save"`
}

func (a *App) handleBulkCommand(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	var req bulkReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	commands := splitLines(req.Commands)
	if len(req.IPs) == 0 || len(commands) == 0 {
		writeErr(w, http.StatusBadRequest, "IP e comandi obbligatori")
		return
	}

	var targets []*store.Device
	for _, ip := range req.IPs {
		d, err := a.store.GetDevice(ip)
		if err != nil || d == nil || !canSeeTenant(scoped, d.Tenant) {
			continue
		}
		targets = append(targets, d)
	}
	if len(targets) == 0 {
		writeErr(w, http.StatusBadRequest, "nessun dispositivo valido")
		return
	}

	job := a.newJob(len(targets))
	go a.runBulk(job.ID, targets, commands, req.Mode, req.Save)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID, "total": len(targets)})
}

func (a *App) runBulk(jobID string, targets []*store.Device, commands []string, mode string, save bool) {
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(8)
	for _, d := range targets {
		d := d
		g.Go(func() error {
			dctx, cancel := context.WithTimeout(ctx, 45*time.Second)
			defer cancel()
			result := a.runCommandsOn(dctx, d, commands, mode, save)
			a.updateJob(jobID, func(j *Job) {
				j.Progress++
				j.Results = append(j.Results, map[string]any{
					"ip":       d.IP,
					"hostname": d.Hostname,
					"result":   result,
				})
			})
			return nil
		})
	}
	_ = g.Wait()
	a.updateJob(jobID, func(j *Job) { j.Status = "done" })
}

func (a *App) runCommandsOn(ctx context.Context, d *store.Device, commands []string, mode string, save bool) map[string]any {
	sess, err := collect.Dial(ctx, d.IP, a.resolveCreds(d))
	if err != nil {
		return map[string]any{"status": "error", "message": err.Error()}
	}
	defer sess.Close()

	var out string
	if mode == "config" {
		out = sess.RunConfig(commands)
	} else {
		var b strings.Builder
		for _, c := range commands {
			b.WriteString(sess.Run(c))
			b.WriteString("\n")
		}
		out = b.String()
	}
	if save {
		sess.WriteMemory()
	}
	return map[string]any{"status": "success", "output": strings.TrimSpace(out)}
}

// ---- Comando singolo (send-command) ----

type sendCommandReq struct {
	IP      string `json:"ip"`
	Command string `json:"command"`
}

// handleSendCommand esegue un singolo comando CLI su un dispositivo (one-shot),
// porto di POST /api/send-command in app_server.py. Blocca i comandi in
// blacklist con audit-log, come il riferimento Python.
func (a *App) handleSendCommand(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req sendCommandReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !isCommandSafe(req.Command) {
		a.auditLog("Tentativo bloccato di esecuzione comando non sicuro '" + req.Command +
			"' su '" + req.IP + "' dall'utente '" + claims.Username + "'.")
		writeErr(w, http.StatusBadRequest, "Comando non consentito per motivi di sicurezza (in blacklist).")
		return
	}

	d, err := a.store.GetDevice(req.IP)
	if err != nil || d == nil {
		writeErr(w, http.StatusNotFound, "Dispositivo non presente in inventario")
		return
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, d.Tenant) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return
	}

	a.auditLog("Comando CLI '" + req.Command + "' richiesto su dispositivo '" + req.IP +
		"' dall'utente '" + claims.Username + "' (One-Shot API).")

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	res := a.runCommandsOn(ctx, d, []string{req.Command}, "exec", false)
	writeJSON(w, http.StatusOK, res)
}

// ---- Subnet scan ----

type scanReq struct {
	Network         string `json:"network"`
	Vendor          string `json:"vendor"`
	Group           string `json:"group"`
	AutoAdd         bool   `json:"auto_add"`
	UseDefaultCreds bool   `json:"use_default_creds"`
}

func (a *App) handleScanSubnet(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	var req scanReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	hosts, err := expandNetwork(req.Network)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(hosts) == 0 {
		writeErr(w, http.StatusBadRequest, "nessun host da scansionare")
		return
	}
	if len(hosts) > 1024 {
		writeErr(w, http.StatusBadRequest, "subnet troppo grande (max /22)")
		return
	}
	if req.Group == "" {
		req.Group = "Generale"
	}
	if !canSeeTenant(scoped, req.Group) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return
	}
	if req.Vendor == "" {
		req.Vendor = "cisco"
	}

	job := a.newJob(len(hosts))
	go a.runScan(job.ID, hosts, req)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": job.ID, "total_hosts": len(hosts)})
}

func (a *App) runScan(jobID string, hosts []string, req scanReq) {
	creds := collect.Credentials{Username: a.cfg.DefaultUser, Password: a.cfg.DefaultPass, EnableSecret: a.cfg.DefaultSecret}
	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(32)
	for _, ip := range hosts {
		ip := ip
		g.Go(func() error {
			hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			result := map[string]any{"ip": ip, "reachable": false, "ssh_ok": false, "hostname": "", "vendor": req.Vendor, "added": false}
			if collect.Ping(hctx, ip) {
				result["reachable"] = true
				if res := collect.RunBackupAndTriage(hctx, ip, creds); res.Status == "success" {
					result["ssh_ok"] = true
					result["hostname"] = res.Hostname
					if req.AutoAdd {
						if err := a.store.UpsertDeviceForPromotion(ip, strings.ToLower(req.Vendor), req.Group, res.Hostname); err == nil {
							_ = a.store.UpsertVersion(ip, strings.ToLower(req.Vendor), res.Version, "online")
							result["added"] = true
						}
					}
				}
			}
			a.updateJob(jobID, func(j *Job) {
				j.Progress++
				j.Results = append(j.Results, result)
			})
			return nil
		})
	}
	_ = g.Wait()
	a.updateJob(jobID, func(j *Job) { j.Status = "done" })
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimRight(l, "\r"); strings.TrimSpace(t) != "" {
			out = append(out, t)
		}
	}
	return out
}

// expandNetwork accetta "a.b.c.d/nn" oppure "a.b.c.d m.m.m.m" e ritorna gli host.
func expandNetwork(spec string) ([]string, error) {
	spec = strings.TrimSpace(spec)
	var ipNet *net.IPNet
	if strings.Contains(spec, "/") {
		_, n, err := net.ParseCIDR(spec)
		if err != nil {
			return nil, errString("CIDR non valido")
		}
		ipNet = n
	} else {
		parts := strings.Fields(spec)
		if len(parts) != 2 {
			return nil, errString("formato rete non valido (usa CIDR o 'ip maschera')")
		}
		ip := net.ParseIP(parts[0]).To4()
		mask := net.ParseIP(parts[1]).To4()
		if ip == nil || mask == nil {
			return nil, errString("indirizzo o maschera non validi")
		}
		ipNet = &net.IPNet{IP: ip.Mask(net.IPMask(mask)), Mask: net.IPMask(mask)}
	}
	var hosts []string
	for ip := cloneIP(ipNet.IP.Mask(ipNet.Mask)); ipNet.Contains(ip); incIP(ip) {
		hosts = append(hosts, ip.String())
	}
	// Rimuovi network e broadcast per prefissi < /31.
	if len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
