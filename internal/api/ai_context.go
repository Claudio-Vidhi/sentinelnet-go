// Package api: costruttori di contesto per l'AI Assistant (porta dei
// _*_context di routers/ai.py). Ogni funzione produce un blocco di testo già
// scoped per tenant/utente; l'assemblaggio e la redazione avvengono altrove
// (endpoint /api/ai/chat e choke-point in internal/ai). Convenzione d'errore:
// i builder che possono fallire scrivono la risposta su w e ritornano ok=false.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// deviceInventorySummary: riepilogo testuale dell'inventario, scoped per sede.
// scoped==nil = admin (nessun filtro). Porta di _device_inventory_summary.
func (a *App) deviceInventorySummary(scoped []string) string {
	devices, _ := a.store.ListDevices()
	filtered := make([]*store.Device, 0, len(devices))
	for _, d := range devices {
		if canSeeTenant(scoped, d.Tenant) {
			filtered = append(filtered, d)
		}
	}
	lines := []string{fmt.Sprintf("Inventario dispositivi (%d totali):", len(filtered))}
	shown := filtered
	if len(shown) > 200 {
		shown = shown[:200]
	}
	for _, d := range shown {
		host := d.Hostname
		if host == "" {
			host = "(senza hostname)"
		}
		lines = append(lines, fmt.Sprintf("- %s | %s | vendor=%s | sede=%s",
			d.IP, host, d.Vendor, d.Tenant))
	}
	if len(filtered) > 200 {
		lines = append(lines, fmt.Sprintf("... e altri %d dispositivi (troncato).", len(filtered)-200))
	}
	return strings.Join(lines, "\n")
}

// deviceRunningConfigContext: running-config più recente di un dispositivo,
// con verifica di scoping. Porta di _device_running_config_context.
func (a *App) deviceRunningConfigContext(w http.ResponseWriter, r *http.Request, ip string) (string, bool) {
	if _, ok := a.assertDeviceAllowed(w, r, ip); !ok {
		return "", false
	}
	text, ok := configanalyzer.LoadBackupRunningConfig(a.cfg.BackupDir(), ip)
	if !ok {
		writeErr(w, http.StatusNotFound, "Nessun backup trovato per "+ip+".")
		return "", false
	}
	return fmt.Sprintf("Running-config di %s:\n\n%s", ip, text), true
}

// fortigateLiveContext: configurazione LIVE completa di un FortiGate + stato di
// sistema, best-effort. Porta di _fortigate_live_context. La risoluzione del
// device può fallire (scoping/vendor → risposta HTTP, ok=false); i fetch dei
// dati live no: eventuali errori finiscono come testo nel blocco.
func (a *App) fortigateLiveContext(w http.ResponseWriter, r *http.Request, ip string) (string, bool) {
	d, c, ok := a.fgtDeviceByIP(w, r, ip)
	if !ok {
		return "", false
	}
	lines := []string{fmt.Sprintf("## FortiGate %s — dati live", ip)}
	if st, err := c.SystemStatus(r.Context(), a.fgtSSH(d)); err != nil {
		lines = append(lines, fmt.Sprintf("Stato sistema non disponibile: %v", err))
	} else {
		lines = append(lines, fmt.Sprintf("Stato sistema (fonte %s):\n%s",
			st.Source, truncRunes(jsonString(st.Data), 4000)))
	}
	if cfg, err := c.FullConfig(r.Context(), a.fgtSSH(d)); err != nil {
		lines = append(lines, fmt.Sprintf("Configurazione live non disponibile: %v", err))
	} else {
		text := configText(cfg.Data)
		if len(text) > 120000 {
			text = text[:120000] + "\n... [config troncata]"
		}
		lines = append(lines, fmt.Sprintf("Configurazione completa (fonte %s):\n%s", cfg.Source, text))
	}
	return strings.Join(lines, "\n\n"), true
}

// tenantContextBlock: contesto completo di un tenant/sede (dispositivi, gruppo,
// sedi VPN, MAC history) scoped e verificato. Porta di _tenant_context_block.
func (a *App) tenantContextBlock(w http.ResponseWriter, r *http.Request, tenant string) (string, bool) {
	claims := claimsFrom(r.Context())
	exists, _ := a.store.TenantExists(tenant)
	if !exists {
		writeErr(w, http.StatusNotFound, "Sede/tenant '"+tenant+"' non trovata.")
		return "", false
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, tenant) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return "", false
	}

	allDevices, _ := a.store.ListDevices()
	devices := []map[string]any{}
	siteIDs := map[string]bool{}
	for _, d := range allDevices {
		if d.Tenant != tenant {
			continue
		}
		devices = append(devices, map[string]any{
			"IP": d.IP, "Hostname": d.Hostname, "Vendor": d.Vendor, "Site": d.Site,
		})
		sid := d.Site
		if sid == "" {
			sid = "central"
		}
		siteIDs[sid] = true
	}

	var groupInfo map[string]any
	if tenants, err := a.store.ListTenants(); err == nil {
		for _, tn := range tenants {
			if tn.Name == tenant {
				groupInfo = map[string]any{"description": tn.Description}
				break
			}
		}
	}

	sites := []map[string]any{}
	for sid := range siteIDs {
		if s, err := a.store.GetSite(sid); err == nil && s != nil {
			site := map[string]any{"id": s.ID, "name": s.Name, "mode": s.Mode, "subnets": s.Subnets}
			if s.LastSeen != nil {
				site["last_seen"] = *s.LastSeen
			}
			sites = append(sites, site)
		}
	}

	sightings, macs, switches, _ := a.store.MacStatsScoped([]string{tenant})
	macStats := map[string]any{
		"sightings": sightings, "unique_macs": macs, "switches": switches,
	}
	if a.obsMgr != nil {
		macStats["retention_days"] = a.obsMgr.FlowRetentionDays()
	}

	recent, _ := a.store.SearchSightings("", "", "", "", []string{tenant}, 15)
	macRecent := make([]map[string]any, 0, len(recent))
	for _, s := range recent {
		macRecent = append(macRecent, map[string]any{
			"mac": s.Mac, "switch_ip": s.SwitchIP, "interface": s.Interface,
			"vlan": s.Vlan, "last_seen": s.LastSeen,
		})
	}

	return ai.BuildTenantContext(ai.TenantContextArgs{
		Tenant:    tenant,
		Devices:   devices,
		GroupInfo: groupInfo,
		Site:      sites,
		MacStats:  macStats,
		MacRecent: macRecent,
	}), true
}

// jsonString serializza un valore per il contesto (equivalente di json.dumps
// ensure_ascii=False).
func jsonString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// configText: la config completa può essere già stringa (SSH) o struttura
// (REST); nel secondo caso la si serializza in JSON. Porta di
// `cfg["data"] if isinstance(cfg["data"], str) else json.dumps(...)`.
func configText(data any) string {
	if s, ok := data.(string); ok {
		return s
	}
	return jsonString(data)
}

func truncRunes(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}
