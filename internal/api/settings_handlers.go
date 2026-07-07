package api

import (
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
)

// bindHostSettingKey: chiave nella tabella settings dove viene persistito
// l'host di bind scelto dall'utente (equivalente all'"host" di app_settings.json in Python).
const bindHostSettingKey = "bind_host"

// listLocalIPs enumera gli IP locali (IPv4) delle interfacce di rete, porto di
// list_local_ips() in app_server.py. Antepone sempre "0.0.0.0" e "127.0.0.1".
func listLocalIPs() []string {
	set := map[string]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil {
				continue
			}
			s := ip4.String()
			if strings.HasPrefix(s, "169.254.") || s == "0.0.0.0" || s == "127.0.0.1" {
				continue
			}
			set[s] = true
		}
	}
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	return append([]string{"0.0.0.0", "127.0.0.1"}, ips...)
}

// resolveBindHost determina l'host su cui il server deve mettersi in ascolto:
// env SENTINELNET_HOST > valore persistito > "127.0.0.1". Porto di resolve_bind_host().
func resolveBindHost(getSetting func(key, def string) string) string {
	if env := os.Getenv("SENTINELNET_HOST"); env != "" {
		return env
	}
	if getSetting != nil {
		if cfg := getSetting(bindHostSettingKey, ""); cfg != "" {
			return cfg
		}
	}
	return "127.0.0.1"
}

// ResolveListenAddr calcola l'indirizzo host:porta di ascolto all'avvio,
// rispettando la precedenza di resolve_bind_host() in Python: env
// SENTINELNET_HOST > host persistito nelle impostazioni > "127.0.0.1".
// La porta segue SENTINELNET_PORT (default 8000).
func (a *App) ResolveListenAddr() string {
	host := resolveBindHost(a.store.GetSetting)
	port := "8000"
	if p := os.Getenv("SENTINELNET_PORT"); p != "" {
		port = p
	}
	return host + ":" + port
}

type networkSettingsResp struct {
	ConfiguredHost string   `json:"configured_host"`
	EffectiveHost  string   `json:"effective_host"`
	EnvOverride    bool     `json:"env_override"`
	Port           int      `json:"port"`
	LocalIPs       []string `json:"local_ips"`
}

// handleGetNetworkSettings: GET /api/settings/network (solo admin).
func (a *App) handleGetNetworkSettings(w http.ResponseWriter, r *http.Request) {
	envHost := os.Getenv("SENTINELNET_HOST")
	configured := a.store.GetSetting(bindHostSettingKey, "")
	effective := envHost
	if effective == "" {
		effective = configured
	}
	if effective == "" {
		effective = "127.0.0.1"
	}
	port := 8000
	if p := os.Getenv("SENTINELNET_PORT"); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			port = n
		}
	}
	writeJSON(w, http.StatusOK, networkSettingsResp{
		ConfiguredHost: configured,
		EffectiveHost:  effective,
		EnvOverride:    envHost != "",
		Port:           port,
		LocalIPs:       listLocalIPs(),
	})
}

type networkSettingsReq struct {
	Host string `json:"host"`
}

// handleSetNetworkSettings: POST /api/settings/network (solo admin). Valida
// che l'host sia tra gli IP locali o 0.0.0.0/127.0.0.1, poi lo persiste.
func (a *App) handleSetNetworkSettings(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req networkSettingsReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	host := strings.TrimSpace(req.Host)
	valid := map[string]bool{}
	for _, ip := range listLocalIPs() {
		valid[ip] = true
	}
	if !valid[host] {
		writeErr(w, http.StatusBadRequest, "Host '"+host+"' non valido o non disponibile sulla LAN.")
		return
	}
	if err := a.store.SetSetting(bindHostSettingKey, host); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("IP di bind impostato a '" + host + "' dall'utente '" + claims.Username + "' (applicato al riavvio).")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "success",
		"restart_required": true,
		"host":             host,
	})
}
