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
// La porta segue la stessa precedenza: env SENTINELNET_PORT > porta
// persistita da /api/settings/app > 8000. L'ambiente vince perché è il modo in
// cui si forza la porta in un container o in un servizio, e non deve dipendere
// dal contenuto del database.
func (a *App) ResolveListenAddr() string {
	host := resolveBindHost(a.store.GetSetting)
	port := os.Getenv("SENTINELNET_PORT")
	if port == "" {
		port = a.store.GetSetting(appPortSettingKey, "")
	}
	if port == "" {
		port = strconv.Itoa(defaultAppPort)
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

type cliBlacklistReq struct {
	CliBlacklistOperators bool `json:"cli_blacklist_operators"`
}

// handleGetCliBlacklistSettings: GET /api/settings/cli-blacklist — stato
// dell'applicazione della blacklist CLI agli operatori (default: attiva).
func (a *App) handleGetCliBlacklistSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"cli_blacklist_operators": a.blacklistAppliesToOperators(),
	})
}

// handleSetCliBlacklistSettings: POST /api/settings/cli-blacklist.
//
// Disattivarla consente agli operatori i comandi distruttivi, quindi la
// modifica è sempre in audit: è un cambio di postura di sicurezza, non una
// preferenza dell'interfaccia.
func (a *App) handleSetCliBlacklistSettings(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req cliBlacklistReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	// Si persiste "false" solo per la disattivazione esplicita: qualunque
	// altro valore lascia la blacklist attiva, come da blacklistAppliesToOperators.
	value := "true"
	stato := "attivata"
	if !req.CliBlacklistOperators {
		value, stato = "false", "disattivata"
	}
	if err := a.store.SetSetting(cliBlacklistOperatorsKey, value); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Blacklist comandi CLI per gli operatori " + stato +
		" dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                  "success",
		"cli_blacklist_operators": req.CliBlacklistOperators,
	})
}

// fortigatePreviewSettingKey: flag della tab "FortiGate LIVE" (preview),
// disattivata per default.
const fortigatePreviewSettingKey = "fortigate_preview_enabled"

type fortigatePreviewReq struct {
	Enabled bool `json:"enabled"`
}

// handleGetFortigatePreviewSettings: GET /api/settings/fortigate-preview.
func (a *App) handleGetFortigatePreviewSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"fortigate_preview": a.store.GetSetting(fortigatePreviewSettingKey, "") == "true",
	})
}

// handleSetFortigatePreviewSettings: POST /api/settings/fortigate-preview.
//
// Al contrario della blacklist, qui il default è "disattivata": è una funzione
// in preview, e solo un "true" esplicito la accende.
func (a *App) handleSetFortigatePreviewSettings(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req fortigatePreviewReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	value, stato := "false", "disattivata"
	if req.Enabled {
		value, stato = "true", "attivata"
	}
	if err := a.store.SetSetting(fortigatePreviewSettingKey, value); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Tab FortiGate LIVE (preview) " + stato + " dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "fortigate_preview": req.Enabled,
	})
}

// Impostazioni applicazione avanzate: GET/POST /api/settings/app.
//
// Il Python espone otto chiavi (porta, TLS, CORS, no_browser e le tre finestre
// di retention). Qui se ne espone solo il sottoinsieme che il binario Go
// onora davvero:
//
//   - TLS, CORS e no_browser non sono implementati nel server Go. Restituirli
//     produrrebbe un form in cui l'operatore imposta un certificato e non
//     ottiene HTTPS: un campo che mente è peggio di un campo assente.
//   - le finestre di retention esistono, ma appartengono alla configurazione
//     dell'osservabilità (/api/observability/config), che è dove la UI le
//     modifica. Duplicarle qui creerebbe due sorgenti per lo stesso valore.
//
// Resta quindi la porta, che ResolveListenAddr legge davvero all'avvio.
// Divergenza documentata in DIVERGENZE-DAL-PYTHON.md §9.
const (
	appPortSettingKey = "app_port"
	defaultAppPort    = 8000
)

// handleGetAppSettings: GET /api/settings/app.
func (a *App) handleGetAppSettings(w http.ResponseWriter, r *http.Request) {
	dataDir := ""
	if a.cfg != nil {
		dataDir = a.cfg.DataDir
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"settings":      a.appSettings(),
		"env_overrides": map[string]bool{"port": os.Getenv("SENTINELNET_PORT") != ""},
		"defaults":      map[string]any{"port": defaultAppPort},
		"data_dir":      dataDir,
	})
}

// handleSetAppSettings: POST /api/settings/app.
//
// Una chiave non gestita è rifiutata con 400 invece di essere ignorata in
// silenzio: se la UI prova a impostare un certificato TLS, l'operatore deve
// sapere che non è stato salvato, non scoprirlo quando l'HTTPS non parte.
func (a *App) handleSetAppSettings(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req map[string]any
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	for k, v := range req {
		if k != "port" {
			writeErr(w, http.StatusBadRequest, "Invalid key: '"+k+"'.")
			return
		}
		// null o stringa vuota: si torna al default, cioè si rimuove il valore.
		if v == nil || v == "" {
			if err := a.store.SetSetting(appPortSettingKey, ""); err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			continue
		}
		port, ok := toInt(v)
		if !ok || port < 1 || port > 65535 {
			writeErr(w, http.StatusBadRequest, "Invalid port (1-65535).")
			return
		}
		if err := a.store.SetSetting(appPortSettingKey, strconv.Itoa(port)); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	a.auditLog("Impostazioni applicazione aggiornate da '" + claims.Username +
		"' (riavvio richiesto).")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "success",
		"restart_required": true,
		"settings":         a.appSettings(),
	})
}

// appSettings è lo stato corrente delle impostazioni gestite.
func (a *App) appSettings() map[string]any {
	out := map[string]any{}
	if v := a.store.GetSetting(appPortSettingKey, ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			out["port"] = n
		}
	}
	return out
}

// toInt accetta i numeri JSON (float64) e le stringhe numeriche, come fa il
// Python con int(v).
func toInt(v any) (int, bool) {
	switch t := v.(type) {
	case float64:
		return int(t), t == float64(int(t))
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		return n, err == nil
	}
	return 0, false
}
