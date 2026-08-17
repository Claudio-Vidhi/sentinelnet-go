package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/flowpath"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/rules"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/suppression"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/timeline"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/go-chi/chi/v5"
)

func (a *App) getCorrelationRulesOverrides() map[string]any {
	raw := a.store.GetSetting("correlation_rules", "{}")
	var m map[string]any
	_ = json.Unmarshal([]byte(raw), &m)
	if m == nil {
		m = map[string]any{}
	}
	return m
}

func (a *App) getSuppressions() map[string]suppression.Rule {
	raw := a.store.GetSetting("suppressions", "{}")
	var m map[string]suppression.Rule
	_ = json.Unmarshal([]byte(raw), &m)
	if m == nil {
		m = map[string]suppression.Rule{}
	}
	return m
}

func (a *App) saveSuppressions(m map[string]suppression.Rule) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return a.store.SetSetting("suppressions", string(b))
}

// GET /api/incidents/rules
func (a *App) handleListCorrelationRules(w http.ResponseWriter, r *http.Request) {
	overrides := a.getCorrelationRulesOverrides()
	cat := rules.Catalog(overrides)
	writeJSON(w, http.StatusOK, map[string]any{"rules": cat})
}

// POST /api/incidents/rules/{rule_id}/parameters
func (a *App) handleSetRuleParameters(w http.ResponseWriter, r *http.Request) {
	ruleID := chi.URLParam(r, "rule_id")
	rDef, ok := rules.Rules[ruleID]
	if !ok {
		writeErr(w, http.StatusNotFound, "Rule not found.")
		return
	}

	var payload map[string]any
	if err := decodeJSON(r, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	specs := map[string]rules.ParameterSpec{}
	for _, p := range rDef.Parameters {
		specs[p.Name] = p
	}

	accepted := map[string]float64{}
	for name, val := range payload {
		spec, exists := specs[name]
		if !exists {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("Parametro sconosciuto: '%s'.", name))
			return
		}
		num, ok := val.(float64)
		if !ok {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("'%s' deve essere numerico.", name))
			return
		}
		if num < spec.Min || num > spec.Max {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf("'%s' fuori intervallo (%v–%v).", name, spec.Min, spec.Max))
			return
		}
		accepted[name] = num
	}

	overrides := a.getCorrelationRulesOverrides()
	ruleMap, _ := overrides[ruleID].(map[string]any)
	if ruleMap == nil {
		ruleMap = map[string]any{}
	}
	for k, v := range accepted {
		ruleMap[k] = v
	}
	overrides[ruleID] = ruleMap

	b, _ := json.Marshal(overrides)
	_ = a.store.SetSetting("correlation_rules", string(b))

	claims := claimsFrom(r.Context())
	username := ""
	if claims != nil {
		username = claims.Username
	}
	a.auditLog(fmt.Sprintf("Soglie della regola %s aggiornate da '%s'.", ruleID, username))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "success",
		"rule_id":   ruleID,
		"effective": rules.ParamsFor(ruleID, overrides),
	})
}

const instabilityWindowS int64 = 86400

// GET /api/incidents/interfaces
func (a *App) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"interfaces":      []any{},
			"window_s":        instabilityWindowS,
			"min_transitions": 4,
			"suppressions":    []any{},
		})
		return
	}

	now := time.Now().Unix()
	suppMap := a.getSuppressions()

	type ifaceItem struct {
		Tenant      string `json:"tenant"`
		DeviceIP    string `json:"device_ip"`
		Hostname    string `json:"hostname"`
		Interface   string `json:"interface"`
		TS          int64  `json:"ts"`
		Link        any    `json:"link"`
		AdminStatus any    `json:"admin_status"`
		Transitions int    `json:"transitions"`
		Suppressed  bool   `json:"suppressed"`
		Scope       string `json:"scope,omitempty"`
		FromTS      *int64 `json:"from_ts,omitempty"`
		ToTS        *int64 `json:"to_ts,omitempty"`
		Note        string `json:"note,omitempty"`
	}

	hostnames := map[string]string{}
	devices, err := a.store.ListDevices()
	if err == nil {
		for _, d := range devices {
			hostnames[d.IP] = d.Hostname
		}
	}

	query := `SELECT tenant, device_ip, interface, attrs_json, ts FROM events
	          WHERE event_type = 'interface.state'`
	var args []any
	if allowedTenants != nil {
		if len(allowedTenants) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{
				"interfaces":      []any{},
				"window_s":        instabilityWindowS,
				"min_transitions": 4,
				"suppressions":    []any{},
			})
			return
		}
		query += fmt.Sprintf(` AND tenant IN (%s)`, sqlInPlaceholders(len(allowedTenants)))
		for _, t := range allowedTenants {
			args = append(args, t)
		}
	}
	query += ` AND id IN (SELECT MAX(id) FROM events WHERE event_type = 'interface.state' GROUP BY tenant, entity_id)
	          ORDER BY device_ip, interface LIMIT 500`

	rows, err := a.obs.DB.Query(query, args...)
	var items []ifaceItem
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var tenant, devIP, iface, attrsJSON string
			var ts int64
			if err := rows.Scan(&tenant, &devIP, &iface, &attrsJSON, &ts); err != nil {
				continue
			}
			var attrs map[string]any
			_ = json.Unmarshal([]byte(attrsJSON), &attrs)

			rule := suppression.Active(suppMap, tenant, "ip:"+devIP, iface, now)
			item := ifaceItem{
				Tenant:      tenant,
				DeviceIP:    devIP,
				Hostname:    hostnames[devIP],
				Interface:   iface,
				TS:          ts,
				Link:        attrs["link"],
				AdminStatus: attrs["admin_status"],
				Suppressed:  rule != nil,
			}
			if rule != nil {
				scope := "interface"
				if rule.Interface == "" || rule.Interface == "*" {
					scope = "device"
				}
				item.Scope = scope
				item.FromTS = rule.FromTS
				item.ToTS = rule.ToTS
				item.Note = rule.Note
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	var visibleSupps []suppression.Rule
	for k, sup := range suppMap {
		if allowedTenants != nil && !containsStr(allowedTenants, sup.Tenant) {
			continue
		}
		sup.Key = k
		sup.Expired = suppression.Expired(sup, now)
		visibleSupps = append(visibleSupps, sup)
	}
	sort.Slice(visibleSupps, func(i, j int) bool {
		return visibleSupps[i].Key < visibleSupps[j].Key
	})

	overrides := a.getCorrelationRulesOverrides()
	flappingParams := rules.ParamsFor("IFACE_FLAPPING_001", overrides)
	minTrans := int(flappingParams["min_transitions"])
	if minTrans == 0 {
		minTrans = 4
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"interfaces":      items,
		"window_s":        instabilityWindowS,
		"min_transitions": minTrans,
		"suppressions":    visibleSupps,
	})
}

// POST /api/incidents/interfaces/expected
func (a *App) handleSetSuppression(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var payload struct {
		Tenant     string `json:"tenant"`
		DeviceIP   string `json:"device_ip"`
		Interface  string `json:"interface"`
		FromTS     *int64 `json:"from_ts"`
		ToTS       *int64 `json:"to_ts"`
		Suppressed bool   `json:"suppressed"`
		Note       string `json:"note"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "Payload non valido")
		return
	}

	if payload.Tenant == "" || payload.DeviceIP == "" {
		writeErr(w, http.StatusBadRequest, "tenant e device_ip sono richiesti.")
		return
	}

	if allowedTenants != nil && !containsStr(allowedTenants, payload.Tenant) {
		writeErr(w, http.StatusNotFound, "Interface not found.")
		return
	}

	if payload.FromTS != nil && payload.ToTS != nil && *payload.ToTS <= *payload.FromTS {
		writeErr(w, http.StatusBadRequest, "La fine della finestra precede l'inizio.")
		return
	}

	entityKey := "ip:" + payload.DeviceIP
	k := suppression.Key(payload.Tenant, entityKey, payload.Interface)
	suppMap := a.getSuppressions()

	action := ""
	if payload.Suppressed {
		suppMap[k] = suppression.Rule{
			Tenant:     payload.Tenant,
			EntityKey:  entityKey,
			DeviceIP:   payload.DeviceIP,
			Interface:  payload.Interface,
			FromTS:     payload.FromTS,
			ToTS:       payload.ToTS,
			Note:       payload.Note,
			By:         claims.Username,
			CreatedTS:  time.Now().Unix(),
			Suppressed: true,
		}
		window := "sempre"
		if payload.ToTS != nil {
			window = fmt.Sprintf("fino a %d", *payload.ToTS)
		}
		action = fmt.Sprintf("soppressa (%s)", window)
	} else {
		delete(suppMap, k)
		action = "riportata sotto osservazione"
	}

	_ = a.saveSuppressions(suppMap)
	targetDesc := payload.DeviceIP
	if payload.Interface != "" {
		targetDesc += ":" + payload.Interface
	} else {
		targetDesc += ":tutto l apparato"
	}
	a.auditLog(fmt.Sprintf("%s (%s) %s da '%s'.", targetDesc, payload.Tenant, action, claims.Username))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"key":        k,
		"suppressed": payload.Suppressed,
	})
}

// GET /api/incidents
func (a *App) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"window": "24h", "status": "new", "page": 0, "incidents": []any{},
		})
		return
	}

	status := r.URL.Query().Get("status")
	if status == "" {
		status = "new"
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "24h"
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 0 {
		page = 0
	}

	seconds := parseWindowSeconds(window)
	cutoff := time.Now().Unix() - seconds

	incidents, err := a.obs.ListIncidents(cutoff, status, allowedTenants, limit, page*limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window":    window,
		"status":    status,
		"page":      page,
		"incidents": incidents,
	})
}

// GET /api/incidents/{id}
func (a *App) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	inc, err := a.obs.GetIncident(id)
	if err != nil || inc == nil {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}
	if allowedTenants != nil && !containsStr(allowedTenants, inc.Tenant) {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}

	entries, _ := timeline.Build(a.obs.DB, a.store, id)
	conclusions, _ := a.obs.PreviousConclusions(id)

	srcIP, dstIP, _ := a.obs.ActiveTriggerEndpoints(id)
	fp := flowpath.Build(a.store, srcIP, dstIP, inc.Tenant, "")

	writeJSON(w, http.StatusOK, map[string]any{
		"incident":             inc,
		"timeline":             entries,
		"previous_conclusions": conclusions,
		"flow_path":            fp,
	})
}

// POST /api/incidents/{id}/status
func (a *App) handleSetIncidentStatus(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	var payload struct {
		Status     string `json:"status"`
		FromStatus string `json:"from_status"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "Payload non valido")
		return
	}

	validTransition := (payload.FromStatus == "new" && payload.Status == "ack") ||
		(payload.FromStatus == "new" && payload.Status == "resolved") ||
		(payload.FromStatus == "ack" && payload.Status == "resolved")

	if !validTransition {
		writeErr(w, http.StatusConflict, fmt.Sprintf("Status transition not allowed: '%s' -> '%s'.", payload.FromStatus, payload.Status))
		return
	}

	inc, err := a.obs.GetIncident(id)
	if err != nil || inc == nil || (allowedTenants != nil && !containsStr(allowedTenants, inc.Tenant)) {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}

	ok, err := a.obs.UpdateIncidentStatus(id, payload.FromStatus, payload.Status)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusConflict, "The incident status changed in the meantime: reload the list.")
		return
	}

	a.auditLog(fmt.Sprintf("Incidente #%d: stato '%s' -> '%s' da '%s'.", id, payload.FromStatus, payload.Status, claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"id":         id,
		"new_status": payload.Status,
	})
}

// POST /api/incidents/{id}/explain
func (a *App) handleExplainIncident(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}

	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	inc, err := a.obs.GetIncident(id)
	if err != nil || inc == nil || (allowedTenants != nil && !containsStr(allowedTenants, inc.Tenant)) {
		writeErr(w, http.StatusNotFound, "Incident not found.")
		return
	}

	profile := a.activeProfile()
	if profile == nil {
		writeErr(w, http.StatusBadRequest, "Nessun profilo AI configurato/attivo. Un amministratore deve crearne uno prima.")
		return
	}

	apiKey := ""
	if profile.APIKeyEnc != "" {
		dec, _ := a.vault.Decrypt(profile.APIKeyEnc)
		apiKey = dec
	}
	if profile.Provider != "ollama" && apiKey == "" {
		writeErr(w, http.StatusBadRequest, "API key non configurata per il profilo AI attivo.")
		return
	}

	entries, _ := timeline.Build(a.obs.DB, a.store, id)

	prompt := buildIncidentNarrativePrompt(inc, entries)
	resp, err := ai.Chat([]ai.Message{{Role: "user", Content: prompt}}, ai.ChatOptions{
		Provider:        profile.Provider,
		Model:           profile.Model,
		APIKey:          apiKey,
		BaseURL:         profile.BaseURL,
		RateLimitRPM:    &profile.RateLimitRPM,
		AllowUnredacted: profile.AllowUnredacted,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	now := time.Now().Unix()
	_ = a.obs.SaveAINarrative(id, resp, now)
	a.auditLog(fmt.Sprintf("Narrativa AI generata per l'incidente #%d da '%s' (provider %s).", id, claims.Username, profile.Provider))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "success",
		"id":              id,
		"ai_narrative":    resp,
		"ai_narrative_ts": now,
		"provider":        profile.Provider,
	})
}

func buildIncidentNarrativePrompt(inc *obsstore.Incident, entries []timeline.Entry) string {
	rulesFired := "nessuna"
	sourcesUsed := "nessuna"
	if inc.Reasoning != nil {
		if rf, ok := inc.Reasoning["rules_fired"].([]any); ok && len(rf) > 0 {
			var s []string
			for _, v := range rf {
				s = append(s, fmt.Sprint(v))
			}
			rulesFired = strings.Join(s, ", ")
		}
		if su, ok := inc.Reasoning["sources_used"].([]any); ok && len(su) > 0 {
			var s []string
			for _, v := range su {
				s = append(s, fmt.Sprint(v))
			}
			sourcesUsed = strings.Join(s, ", ")
		}
	}

	lines := []string{
		"Conclusione deterministica gia' calcolata dalla piattaforma (NON metterla in discussione, esponila):",
		fmt.Sprintf("- causa: %s", inc.CauseKind),
		fmt.Sprintf("- confidenza: %d%%", inc.Confidence),
		fmt.Sprintf("- regole attivate: %s", rulesFired),
		fmt.Sprintf("- fonti corroboranti: %s", sourcesUsed),
		fmt.Sprintf("- entita': %s", inc.EntityKey),
		fmt.Sprintf("- eventi correlati: %d", inc.EventCount),
		"",
		"Timeline (istante, fonte, descrizione):",
	}

	limit := 40
	if len(entries) < limit {
		limit = len(entries)
	}
	for i := 0; i < limit; i++ {
		e := entries[i]
		stamp := time.Unix(e.TS, 0).Format("2006-01-02 15:04:05")
		lines = append(lines, fmt.Sprintf("- %s [%s] %s", stamp, e.Source, e.Text))
	}

	lines = append(lines,
		"",
		"Scrivi in italiano, massimo 8 righe: cosa e' successo, in che ordine, e cosa conviene verificare per primo. Non inventare dati assenti dalla timeline e non proporre una causa diversa da quella indicata.",
	)

	return strings.Join(lines, "\n")
}

func sqlInPlaceholders(n int) string {
	var s []string
	for i := 0; i < n; i++ {
		s = append(s, "?")
	}
	return strings.Join(s, ",")
}

func containsStr(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func parseWindowSeconds(w string) int64 {
	w = strings.ToLower(strings.TrimSpace(w))
	if len(w) == 0 {
		return 86400
	}
	unit := w[len(w)-1]
	numStr := w[:len(w)-1]
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 86400
	}
	switch unit {
	case 'm':
		return n * 60
	case 'h':
		return n * 3600
	case 'd':
		return n * 86400
	default:
		return 86400
	}
}


