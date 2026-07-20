package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/go-chi/chi/v5"
)

// obsSettingsKey è la chiave sotto cui la configurazione viene persistita
// nella tabella settings (equivalente della sezione "observability" di
// app_settings.json nel Python).
const obsSettingsKey = "observability"

var windowRe = regexp.MustCompile(`^(\d{1,4})([mhd])$`)

var windowUnitSeconds = map[string]int64{"m": 60, "h": 3600, "d": 86400}

// parseWindow converte "15m" | "24h" | "7d" in secondi, con tetto massimo.
func parseWindow(w string) (int64, bool) {
	m := windowRe.FindStringSubmatch(w)
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, false
	}
	secs := n * windowUnitSeconds[m[2]]
	if secs <= 0 || secs > obsstore.MaxWindow {
		return 0, false
	}
	return secs, true
}

// obsReady verifica che la pipeline sia collegata.
func (a *App) obsReady(w http.ResponseWriter) bool {
	if a.obs == nil || a.obsMgr == nil {
		writeErr(w, http.StatusServiceUnavailable, "osservabilità non disponibile in questa istanza")
		return false
	}
	return true
}

// obsWindow legge e valida il parametro window, rispondendo 400 se invalido.
func obsWindow(w http.ResponseWriter, r *http.Request, def string) (int64, bool) {
	raw := r.URL.Query().Get("window")
	if raw == "" {
		raw = def
	}
	secs, ok := parseWindow(raw)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Invalid window: use e.g. 15m, 24h, 7d.")
		return 0, false
	}
	return time.Now().Unix() - secs, true
}

func obsLimit(r *http.Request, def int) int {
	n := queryLimit(r.URL.Query().Get("limit"), def)
	if n < 1 {
		return 1
	}
	if n > obsstore.MaxLimit {
		return obsstore.MaxLimit
	}
	return n
}

func (a *App) handleObsTop(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	cutoff, ok := obsWindow(w, r, "15m")
	if !ok {
		return
	}
	q := r.URL.Query()
	metric := q.Get("metric")
	if metric != "packets" {
		metric = "bytes"
	}
	source := q.Get("source")
	switch source {
	case "ipfix", "netflow", "sflow":
	default:
		source = "all"
	}

	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	flows, err := a.obs.TopFlows(cutoff, scoped, metric, source, obsLimit(r, 50))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window": windowOrDefault(q.Get("window"), "15m"),
		"metric": metric, "source": source, "flows": flows,
	})
}

func (a *App) handleObsSyslog(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	cutoff, ok := obsWindow(w, r, "15m")
	if !ok {
		return
	}
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	events, err := a.obs.SyslogEvents(cutoff, scoped, obsLimit(r, 100))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window": windowOrDefault(r.URL.Query().Get("window"), "15m"),
		"events": events,
	})
}

func (a *App) handleObsAnomalies(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	cutoff, ok := obsWindow(w, r, "24h")
	if !ok {
		return
	}
	q := r.URL.Query()
	status := q.Get("status")
	switch status {
	case "new", "ack", "resolved", "all":
	default:
		status = "new"
	}
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 0 {
		page = 0
	}

	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	rows, err := a.obs.Anomalies(cutoff, scoped, status, obsLimit(r, 50), page)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window": windowOrDefault(q.Get("window"), "24h"),
		"status": status, "page": page, "anomalies": rows,
	})
}

// allowedTransitions replica esattamente le transizioni ammesse dal Python.
var allowedTransitions = map[[2]string]bool{
	{"new", "ack"}:      true,
	{"new", "resolved"}: true,
	{"ack", "resolved"}: true,
}

type anomalyStatusReq struct {
	Status     string `json:"status"`
	FromStatus string `json:"from_status"`
}

func (a *App) handleObsAnomalyStatus(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	id, err := strconv.ParseInt(chi.URLParam(r, "event_id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "id evento non valido")
		return
	}
	var req anomalyStatusReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !allowedTransitions[[2]string{req.FromStatus, req.Status}] {
		writeErr(w, http.StatusConflict,
			"Status transition not allowed: '"+req.FromStatus+"' → '"+req.Status+"'.")
		return
	}

	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	switch err := a.obs.TransitionAnomaly(id, req.FromStatus, req.Status, scoped); {
	case err == nil:
	case errors.Is(err, obsstore.ErrAnomalyNotFound):
		writeErr(w, http.StatusNotFound, "Event not found.")
		return
	case errors.Is(err, obsstore.ErrAnomalyStale):
		writeErr(w, http.StatusConflict,
			"The event status changed in the meantime: reload the list.")
		return
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog("Anomalia observability #" + strconv.FormatInt(id, 10) + ": stato '" +
		req.FromStatus + "' → '" + req.Status + "' da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "id": id, "new_status": req.Status,
	})
}

func (a *App) handleObsAPIContext(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	deviceIP := r.URL.Query().Get("device_ip")
	if deviceIP == "" {
		writeErr(w, http.StatusBadRequest, "parametro device_ip obbligatorio")
		return
	}
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	rows, err := a.obs.APIContext(deviceIP, scoped)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_ip": deviceIP, "observations": rows,
	})
}

// --- configurazione ---

// obsConfig legge la configurazione persistita, ricadendo sui default.
func (a *App) obsConfig() observability.Config {
	cfg := observability.DefaultConfig()
	if raw := a.store.GetSetting(obsSettingsKey, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

// StartObservability applica al boot la configurazione persistita.
// Senza pipeline collegata non fa nulla.
func (a *App) StartObservability(ctx context.Context) {
	if a.obsMgr == nil {
		return
	}
	a.obsMgr.Apply(ctx, a.obsConfig())
}

func (a *App) handleObsGetConfig(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	writeJSON(w, http.StatusOK, a.obsConfig())
}

func (a *App) handleObsSetConfig(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	// Si parte dalla configurazione salvata e si applicano solo i campi
	// presenti nel payload, così un salvataggio parziale non azzera il resto.
	cfg := a.obsConfig()
	if err := decodeJSON(r, &cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	for name, lc := range map[string]observability.ListenerConfig{
		"ipfix": cfg.IPFIX, "sflow": cfg.SFlow, "syslog": cfg.Syslog, "netflow": cfg.NetFlow,
	} {
		if !observability.ValidPort(lc.Port) {
			writeErr(w, http.StatusBadRequest, "Invalid port for '"+name+"'.")
			return
		}
	}

	blob, err := json.Marshal(cfg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.store.SetSetting(obsSettingsKey, string(blob)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Applicata a caldo: nessun riavvio del processo.
	a.obsMgr.Apply(r.Context(), cfg)

	claims := claimsFrom(r.Context())
	a.auditLog("Config observability aggiornata da '" + claims.Username +
		"' (applicata a caldo, nessun riavvio).")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "restart_required": false,
		"effective": cfg, "listeners": a.obsMgr.Status(),
	})
}

func (a *App) handleObsHealth(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	counters, gauges := a.obs.Metrics.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":             a.obsConfig().Enabled,
		"listeners":           a.obsMgr.Status(),
		"metrics":             map[string]any{"counters": counters, "gauges": gauges},
		"template_cache_size": a.obsMgr.Decoder().TemplateCacheSize(),
		"db_size_bytes":       a.obs.DBSizeBytes(),
		"schema_version":      1,
	})
}

func windowOrDefault(raw, def string) string {
	if raw == "" {
		return def
	}
	return raw
}
