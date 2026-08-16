package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/audit"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/go-chi/chi/v5"
)

// GET /api/netsec-audit/benchmarks
func (a *App) handleNetSecAuditBenchmarks(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		lang = "it"
	}

	res := map[string][]map[string]any{}
	for bmKey, rulesList := range audit.Benchmarks {
		var list []map[string]any
		for _, r := range rulesList {
			title := r.Title[lang]
			if title == "" {
				title = r.Title["it"]
			}
			remStr := ""
			if str, ok := r.Remediation.(string); ok {
				remStr = str
			} else if m, ok := r.Remediation.(map[string]string); ok {
				remStr = m[lang]
				if remStr == "" {
					remStr = m["it"]
				}
			}
			list = append(list, map[string]any{
				"id":          r.ID,
				"title":       title,
				"severity":    r.Severity,
				"category":    r.Category,
				"vendor":      r.Vendor,
				"ref":         r.Ref,
				"level":       r.Level,
				"automated":   r.Automated,
				"audit":       r.AuditCLI,
				"checks":      r.ChecksDoc,
				"remediation": remStr,
			})
		}
		res[bmKey] = list
	}
	writeJSON(w, http.StatusOK, res)
}

type netsecAuditScanReq struct {
	ConfigText string `json:"config_text"`
	DeviceIP   string `json:"device_ip"`
	DeviceName string `json:"device_name"`
	Benchmark  string `json:"benchmark"`
	Lang       string `json:"lang"`
	Save       bool   `json:"save"`
	RunName    string `json:"run_name"`
}

// POST /api/netsec-audit/scan
func (a *App) handleNetSecAuditScan(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req netsecAuditScanReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	configText := req.ConfigText
	devName := req.DeviceName
	var tenant *string

	if configText == "" && req.DeviceIP != "" && req.DeviceIP != "all" {
		dev, err := a.store.GetDevice(req.DeviceIP)
		if err != nil || dev == nil {
			writeErr(w, http.StatusNotFound, fmt.Sprintf("Dispositivo %s non trovato.", req.DeviceIP))
			return
		}
		if allowedTenants != nil && !containsStr(allowedTenants, dev.Tenant) {
			writeErr(w, http.StatusForbidden, "Dispositivo non consentito per il tuo profilo.")
			return
		}
		tenant = &dev.Tenant
		devName = dev.Hostname
		if devName == "" {
			devName = dev.IP
		}

		backupDir := ""
		if a.cfg != nil {
			backupDir = a.cfg.BackupDir()
		}
		txt, ok := configanalyzer.LoadBackupRunningConfig(backupDir, dev.IP)
		if !ok || strings.TrimSpace(txt) == "" {
			writeErr(w, http.StatusNotFound, fmt.Sprintf("Nessun backup trovato per %s.", req.DeviceIP))
			return
		}
		configText = txt
	} else if configText != "" && devName == "" {
		devName = req.DeviceIP
		if devName == "" {
			devName = "Uploaded Config"
		}
	}

	if strings.TrimSpace(configText) == "" {
		writeErr(w, http.StatusBadRequest, "Nessuna configurazione da analizzare: seleziona un dispositivo con backup o carica un file.")
		return
	}

	result, err := audit.RunNetSecAudit(configText, devName, req.Benchmark, req.Lang)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if req.Save && a.obs != nil {
		now := time.Now().Unix()
		summaryJSON, _ := json.Marshal(result.Summary)
		resultJSON, _ := json.Marshal(result)

		var tenantVal any
		if tenant != nil {
			tenantVal = *tenant
		}

		res, err := a.obs.DB.Exec(
			`INSERT INTO netsec_audit_runs (ts, tenant, device_name, device_ip, benchmark, benchmark_title, vendor, lang, score, summary_json, result_json, actor, run_name)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			now, tenantVal, devName, req.DeviceIP, result.Benchmark, result.BenchmarkTitle, result.Vendor, result.Lang, result.Score, string(summaryJSON), string(resultJSON), claims.Username, req.RunName)
		if err == nil {
			runID, _ := res.LastInsertId()
			result.SavedID = &runID
			a.auditLog(fmt.Sprintf("Audit '%s' salvato nello storico (#%d) da '%s'.", result.Benchmark, runID, claims.Username))
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// GET /api/netsec-audit/history
func (a *App) handleNetSecAuditHistory(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"runs": []any{}, "count": 0})
		return
	}

	tenant := r.URL.Query().Get("tenant")
	deviceIP := r.URL.Query().Get("device_ip")
	benchmark := r.URL.Query().Get("benchmark")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	query := `SELECT id, ts, COALESCE(tenant, ''), COALESCE(device_name, ''), COALESCE(device_ip, ''),
	                 benchmark, benchmark_title, vendor, lang, score, summary_json, COALESCE(actor, ''), COALESCE(run_name, '')
	          FROM netsec_audit_runs WHERE 1=1`
	var args []any

	if tenant != "" {
		if allowedTenants != nil && !containsStr(allowedTenants, tenant) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", tenant))
			return
		}
		query += ` AND tenant = ?`
		args = append(args, tenant)
	} else if allowedTenants != nil {
		if len(allowedTenants) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"runs": []any{}, "count": 0})
			return
		}
		query += fmt.Sprintf(` AND tenant IN (%s)`, sqlInPlaceholders(len(allowedTenants)))
		for _, t := range allowedTenants {
			args = append(args, t)
		}
	}

	if deviceIP != "" {
		query += ` AND device_ip = ?`
		args = append(args, deviceIP)
	}
	if benchmark != "" {
		query += ` AND benchmark = ?`
		args = append(args, benchmark)
	}

	query += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, limit)

	rows, err := a.obs.DB.Query(query, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	type runItem struct {
		ID             int64          `json:"id"`
		TS             int64          `json:"ts"`
		Tenant         string         `json:"tenant"`
		DeviceName     string         `json:"device_name"`
		DeviceIP       string         `json:"device_ip"`
		Benchmark      string         `json:"benchmark"`
		BenchmarkTitle string         `json:"benchmark_title"`
		Vendor         string         `json:"vendor"`
		Lang           string         `json:"lang"`
		Score          *int           `json:"score"`
		Summary        map[string]any `json:"summary"`
		Actor          string         `json:"actor"`
		RunName        string         `json:"run_name"`
	}

	var runs []runItem
	for rows.Next() {
		var item runItem
		var sumJSON string
		if err := rows.Scan(&item.ID, &item.TS, &item.Tenant, &item.DeviceName, &item.DeviceIP,
			&item.Benchmark, &item.BenchmarkTitle, &item.Vendor, &item.Lang, &item.Score,
			&sumJSON, &item.Actor, &item.RunName); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(sumJSON), &item.Summary)
		runs = append(runs, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "count": len(runs)})
}

// GET /api/netsec-audit/history/{run_id}
func (a *App) handleNetSecAuditHistoryDetail(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Audit non trovato.")
		return
	}

	runID, err := strconv.ParseInt(chi.URLParam(r, "run_id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	var tenant sql.NullString
	var resJSON string
	err = a.obs.DB.QueryRow(`SELECT tenant, result_json FROM netsec_audit_runs WHERE id = ?`, runID).Scan(&tenant, &resJSON)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Audit non trovato.")
		return
	}

	if allowedTenants != nil && (!tenant.Valid || !containsStr(allowedTenants, tenant.String)) {
		writeErr(w, http.StatusNotFound, "Audit non trovato.")
		return
	}

	var parsed any
	_ = json.Unmarshal([]byte(resJSON), &parsed)
	writeJSON(w, http.StatusOK, parsed)
}

// DELETE /api/netsec-audit/history/{run_id}
func (a *App) handleNetSecAuditHistoryDelete(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Audit non trovato.")
		return
	}

	runID, err := strconv.ParseInt(chi.URLParam(r, "run_id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	var tenant sql.NullString
	err = a.obs.DB.QueryRow(`SELECT tenant FROM netsec_audit_runs WHERE id = ?`, runID).Scan(&tenant)
	if err != nil {
		writeErr(w, http.StatusNotFound, "Audit non trovato.")
		return
	}
	if allowedTenants != nil && (!tenant.Valid || !containsStr(allowedTenants, tenant.String)) {
		writeErr(w, http.StatusNotFound, "Audit non trovato.")
		return
	}

	_, _ = a.obs.DB.Exec(`DELETE FROM netsec_audit_runs WHERE id = ?`, runID)
	a.auditLog(fmt.Sprintf("Audit run #%d eliminato dallo storico da '%s'.", runID, claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "deleted": runID})
}

// --- Audit Checklist Handlers ---

// GET /api/audit-checklist/templates
func (a *App) handleListAuditTemplates(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	_, _ = audit.SeedDefaultTemplate(a.obs.DB)
	templates, err := audit.ListTemplates(a.obs.DB)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, templates)
}

// GET /api/audit-checklist/templates/{template_id}
func (a *App) handleGetAuditTemplate(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Template non trovato.")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "template_id"), 10, 64)
	tpl, err := audit.GetTemplate(a.obs.DB, id)
	if err != nil || tpl == nil {
		writeErr(w, http.StatusNotFound, "Template non trovato.")
		return
	}
	writeJSON(w, http.StatusOK, tpl)
}

// GET /api/audit-checklist/engagements
func (a *App) handleListAuditEngagements(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	status := r.URL.Query().Get("status")
	tenant := r.URL.Query().Get("tenant")
	engs, err := audit.ListEngagements(a.obs.DB, status, tenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, engs)
}

type createEngagementReq struct {
	CustomerName   string `json:"customer_name"`
	Tenant         string `json:"tenant"`
	SiteID         string `json:"site_id"`
	TemplateID     int64  `json:"template_id"`
	AssignedTo     string `json:"assigned_to"`
	ScopeNotes     string `json:"scope_notes"`
	OnsiteOrRemote string `json:"onsite_or_remote"`
	Interviewee    string `json:"interviewee"`
}

// POST /api/audit-checklist/engagements
func (a *App) handleCreateAuditEngagement(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeErr(w, http.StatusInternalServerError, "Database di osservabilit non disponibile.")
		return
	}
	var req createEngagementReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}
	eng, err := audit.CreateEngagement(a.obs.DB, req.CustomerName, req.Tenant, req.SiteID, req.AssignedTo, req.ScopeNotes, req.OnsiteOrRemote, req.Interviewee, req.TemplateID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, eng)
}

// GET /api/audit-checklist/engagements/{engagement_id}
func (a *App) handleGetAuditEngagement(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Engagement non trovato.")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "engagement_id"), 10, 64)
	eng, err := audit.GetEngagement(a.obs.DB, id)
	if err != nil || eng == nil {
		writeErr(w, http.StatusNotFound, "Engagement non trovato.")
		return
	}
	writeJSON(w, http.StatusOK, eng)
}

type updateItemAssessmentReq struct {
	Status             string `json:"status"`
	Severity           string `json:"severity"`
	FindingText        string `json:"finding_text"`
	RecommendationText string `json:"recommendation_text"`
	AIAssisted         bool   `json:"ai_assisted"`
}

// PUT /api/audit-checklist/engagements/{engagement_id}/items/{item_ref}
func (a *App) handleUpdateAuditItemAssessment(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Engagement non trovato.")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "engagement_id"), 10, 64)
	itemRef := chi.URLParam(r, "item_ref")

	var req updateItemAssessmentReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	err := audit.UpdateItemAssessment(a.obs.DB, id, itemRef, req.Status, req.Severity, req.FindingText, req.RecommendationText, claims.Username, req.AIAssisted)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "engagement_id": id, "item_ref": itemRef})
}

type addEvidenceReq struct {
	ItemRef      string         `json:"item_ref"`
	Kind         string         `json:"kind"`
	Filename     string         `json:"filename"`
	Path         string         `json:"path"`
	Payload      map[string]any `json:"payload"`
	Confidential bool           `json:"confidential"`
}

// POST /api/audit-checklist/engagements/{engagement_id}/evidence
func (a *App) handleAddAuditEvidence(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Engagement non trovato.")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "engagement_id"), 10, 64)

	var req addEvidenceReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}
	evID, err := audit.AddEvidence(a.obs.DB, id, req.ItemRef, req.Kind, req.Filename, req.Path, req.Payload, req.Confidential)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"status": "success", "evidence_id": evID})
}

// GET /api/audit-checklist/engagements/{engagement_id}/report
func (a *App) handleGetAuditReport(w http.ResponseWriter, r *http.Request) {
	if a.obs == nil {
		writeErr(w, http.StatusNotFound, "Engagement non trovato.")
		return
	}
	id, _ := strconv.ParseInt(chi.URLParam(r, "engagement_id"), 10, 64)
	html, err := audit.GenerateAuditReportHTML(a.obs.DB, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

