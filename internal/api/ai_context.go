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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// topFlowsContext: blocco markdown dei top flussi (900s, top 20) scoped per
// tenant, con opzionale vincolo per-tupla keys. Porta di top_flows_context.
// Se l'osservabilità non è collegata, ritorna comunque header + nota vuota.
func (a *App) topFlowsContext(scoped []string, keys []obsstore.FlowKey) string {
	const windowS = 900
	var flows []obsstore.TopFlow
	var anomalies []obsstore.Anomaly
	if a.obs != nil {
		cutoff := time.Now().Unix() - windowS
		flows, anomalies, _ = a.obs.TopFlowsContext(cutoff, scoped, keys, 20)
	}
	lines := []string{fmt.Sprintf("## Top flussi di rete (ultimi %d minuti, %d aggregati)", windowS/60, len(flows))}
	if len(flows) == 0 {
		lines = append(lines, "(nessun flusso registrato nella finestra)")
	}
	for _, f := range flows {
		proto := "?"
		if f.Protocol != nil {
			// Use same protocol map as flowgraph, but uppercase for output
			protoLower := map[int]string{6: "tcp", 17: "udp", 1: "icmp"}
			if name, ok := protoLower[*f.Protocol]; ok {
				proto = strings.ToUpper(name)
			} else {
				proto = strconv.Itoa(*f.Protocol)
			}
		}
		dport := "-"
		if f.DstPort != nil {
			dport = strconv.Itoa(*f.DstPort)
		}
		lines = append(lines, fmt.Sprintf("- [%s] %s → %s %s/%s: %d byte, %d pacchetti",
			f.Tenant, f.SrcIP, f.DstIP, proto, dport, f.TotalBytes, f.TotalPackets))
	}
	if len(anomalies) > 0 {
		lines = append(lines, "\n## Anomalie correlate aperte (ultime 24h)")
		for _, an := range anomalies {
			port := ""
			if an.SwitchPort != "" {
				port = " — porta " + an.SwitchPort
			}
			sev := "?"
			if an.Severity != nil {
				sev = strconv.Itoa(*an.Severity)
			}
			lines = append(lines, fmt.Sprintf("- [%s] %s sev=%s: %s → %s%s",
				an.Tenant, an.Kind, sev, an.SrcIP, an.DstIP, port))
		}
	}
	return strings.Join(lines, "\n")
}

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
		if r := []rune(text); len(r) > 120000 {
			text = string(r[:120000]) + "\n... [config troncata]"
		}
		lines = append(lines, fmt.Sprintf("Configurazione completa (fonte %s):\n%s", cfg.Source, text))
	}
	return strings.Join(lines, "\n\n"), true
}

// assertGroupAllowed verifica prima lo scope (403 se il tenant è fuori dallo
// scope dell'utente, come Python assert_group_allowed) e poi l'esistenza (404).
// Ritorna false dopo aver scritto la risposta d'errore.
func (a *App) assertGroupAllowed(w http.ResponseWriter, r *http.Request, tenant string) bool {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, tenant) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return false
	}
	exists, _ := a.store.TenantExists(tenant)
	if !exists {
		writeErr(w, http.StatusNotFound, "Sede/tenant '"+tenant+"' non trovata.")
		return false
	}
	return true
}

// tenantContextBlock: contesto completo di un tenant/sede (dispositivi, gruppo,
// sedi VPN, MAC history) scoped e verificato. Porta di _tenant_context_block.
func (a *App) tenantContextBlock(w http.ResponseWriter, r *http.Request, tenant string) (string, bool) {
	if !a.assertGroupAllowed(w, r, tenant) {
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

// commonGlobalPrefixes: prefissi di comandi globali IOS considerati "parametri
// d'ambiente" comuni del tenant. Porta di _COMMON_GLOBAL_PREFIXES.
var commonGlobalPrefixes = []string{
	"vtp ", "ntp ", "logging ", "snmp-server ", "aaa ", "ip domain", "ip name-server",
	"ip default-gateway", "clock timezone", "clock summer-time", "spanning-tree ",
	"ip ssh ", "service ", "radius ", "tacacs ",
}

var (
	reVlanLine  = regexp.MustCompile(`^vlan (\d+)\s*$`)
	reIfaceVlan = regexp.MustCompile(`^interface vlan\s*(\d+)$`)
)

// tenantCommonParameters: distilla i parametri COMUNI dell'ambiente di rete di
// un tenant dai backup dei suoi dispositivi. Porta di _tenant_common_parameters.
func (a *App) tenantCommonParameters(w http.ResponseWriter, r *http.Request, tenant string) (string, bool) {
	if !a.assertGroupAllowed(w, r, tenant) {
		return "", false
	}

	allDevices, _ := a.store.ListDevices()
	lineCounts := map[string]int{}
	vlans := map[string]string{} // id -> name
	mgmtSubnets := map[string]bool{}
	analyzed := 0
	for _, d := range allDevices {
		if d.Tenant != tenant || d.IP == "" {
			continue
		}
		content, ok := configanalyzer.LoadBackupRunningConfig(a.cfg.BackupDir(), d.IP)
		if !ok {
			continue
		}
		analyzed++
		lines := strings.Split(content, "\n")
		for i, raw := range lines {
			s := strings.TrimSpace(raw)
			low := strings.ToLower(s)
			indented := strings.HasPrefix(raw, " ")
			if !indented && hasAnyPrefix(low, commonGlobalPrefixes) {
				lineCounts[s]++
			}
			if !indented {
				if m := reVlanLine.FindStringSubmatch(low); m != nil {
					name := ""
					if i+1 < len(lines) {
						nx := strings.TrimSpace(lines[i+1])
						if strings.HasPrefix(strings.ToLower(nx), "name ") {
							name = nx[5:]
						}
					}
					if _, seen := vlans[m[1]]; !seen {
						vlans[m[1]] = name
					}
				}
			}
		}
		if sub := mgmtSubnetFrom(lines); sub != "" {
			mgmtSubnets[sub] = true
		}
		if analyzed >= 15 {
			break
		}
	}
	if analyzed == 0 {
		writeErr(w, http.StatusNotFound, "Nessun backup di configurazione disponibile per il tenant '"+tenant+"'.")
		return "", false
	}

	threshold := (analyzed + 1) / 2
	if threshold < 1 {
		threshold = 1
	}
	common := []string{}
	for l, c := range lineCounts {
		if c >= threshold {
			common = append(common, l)
		}
	}
	sort.Strings(common)

	out := []string{fmt.Sprintf(
		"## Parametri comuni dell'ambiente tenant '%s' (derivati da %d dispositivi)", tenant, analyzed)}
	if len(vlans) > 0 {
		ids := make([]string, 0, len(vlans))
		for id := range vlans {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return atoiSafe(ids[i]) < atoiSafe(ids[j]) })
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			if vlans[id] != "" {
				parts = append(parts, fmt.Sprintf("%s (%s)", id, vlans[id]))
			} else {
				parts = append(parts, id)
			}
		}
		out = append(out, "VLAN in uso: "+strings.Join(parts, ", "))
	}
	if len(mgmtSubnets) > 0 {
		subs := make([]string, 0, len(mgmtSubnets))
		for s := range mgmtSubnets {
			subs = append(subs, s)
		}
		sort.Strings(subs)
		out = append(out, "Subnet di management osservate: "+strings.Join(subs, "; "))
	}
	if len(common) > 0 {
		out = append(out, "Comandi globali comuni (presenti su almeno metà dei dispositivi):")
		for i, l := range common {
			if i >= 120 {
				break
			}
			out = append(out, "  "+l)
		}
	}
	return strings.Join(out, "\n"), true
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// mgmtSubnetFrom cerca il primo blocco "interface vlan N" e, tra le sue righe
// indentate, la prima "ip address A M". Equivalente line-based del regex
// multiline del Python (evita le insidie di \s+ su newline in RE2).
func mgmtSubnetFrom(lines []string) string {
	for i, raw := range lines {
		if strings.HasPrefix(raw, " ") {
			continue
		}
		m := reIfaceVlan.FindStringSubmatch(strings.ToLower(strings.TrimSpace(raw)))
		if m == nil {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if !strings.HasPrefix(lines[j], " ") && strings.TrimSpace(lines[j]) != "" {
				break // fine del blocco interface
			}
			f := strings.Fields(strings.TrimSpace(lines[j]))
			if len(f) >= 4 && f[0] == "ip" && f[1] == "address" {
				return fmt.Sprintf("VLAN %s: %s %s", m[1], f[2], f[3])
			}
		}
	}
	return ""
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
