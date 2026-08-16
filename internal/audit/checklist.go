package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type TemplateItem struct {
	ID               int64  `json:"id"`
	TemplateID       int64  `json:"template_id"`
	Ref              string `json:"ref"`
	SectionNo        int    `json:"section_no"`
	SectionTitle     string `json:"section_title"`
	Title            string `json:"title"`
	GuidanceWhy      string `json:"guidance_why,omitempty"`
	GuidanceGood     string `json:"guidance_good,omitempty"`
	GuidanceHow      string `json:"guidance_how,omitempty"`
	ThresholdsJSON   string `json:"thresholds_json,omitempty"`
	CheckKind        string `json:"check_kind"`
	SeverityDefault  string `json:"severity_default"`
	IsPrerequisite   bool   `json:"is_prerequisite"`
	RequiresEvidence bool   `json:"requires_evidence"`
	SortOrder        int    `json:"sort_order"`
}

type ChecklistTemplate struct {
	ID        int64          `json:"id"`
	Version   int            `json:"version"`
	Name      string         `json:"name"`
	Status    string         `json:"status"`
	CreatedTS int64          `json:"created_ts"`
	CreatedBy string         `json:"created_by"`
	Notes     string         `json:"notes,omitempty"`
	ItemCount int            `json:"item_count,omitempty"`
	Items     []TemplateItem `json:"items,omitempty"`
}

type EngagementItem struct {
	ID                 int64  `json:"id"`
	EngagementID       int64  `json:"engagement_id"`
	ItemRef            string `json:"item_ref"`
	Status             string `json:"status"`
	Severity           string `json:"severity,omitempty"`
	FindingText        string `json:"finding_text,omitempty"`
	RecommendationText string `json:"recommendation_text,omitempty"`
	AIAssisted         bool   `json:"ai_assisted"`
	SectionNo          int    `json:"section_no,omitempty"`
	SectionTitle       string `json:"section_title,omitempty"`
	Title              string `json:"title,omitempty"`
	GuidanceWhy        string `json:"guidance_why,omitempty"`
	GuidanceGood       string `json:"guidance_good,omitempty"`
	GuidanceHow        string `json:"guidance_how,omitempty"`
	IsPrerequisite     bool   `json:"is_prerequisite,omitempty"`
	RequiresEvidence   bool   `json:"requires_evidence,omitempty"`
}

type Engagement struct {
	ID             int64            `json:"id"`
	TemplateID     int64            `json:"template_id"`
	TemplateName   string           `json:"template_name,omitempty"`
	CustomerName   string           `json:"customer_name"`
	Tenant         string           `json:"tenant,omitempty"`
	SiteID         string           `json:"site_id,omitempty"`
	CreatedTS      int64            `json:"created_ts"`
	Status         string           `json:"status"`
	AssignedTo     string           `json:"assigned_to,omitempty"`
	ScopeNotes     string           `json:"scope_notes,omitempty"`
	OnsiteOrRemote string           `json:"onsite_or_remote"`
	Interviewee    string           `json:"interviewee,omitempty"`
	Items          []EngagementItem `json:"items,omitempty"`
	Stats          map[string]int   `json:"stats,omitempty"`
}

type EvidenceRecord struct {
	ID           int64          `json:"id"`
	EngagementID int64          `json:"engagement_id"`
	ItemRef      string         `json:"item_ref"`
	Kind         string         `json:"kind"`
	Filename     string         `json:"filename,omitempty"`
	Path         string         `json:"path,omitempty"`
	PayloadJSON  string         `json:"payload_json,omitempty"`
	Confidential bool           `json:"confidential"`
	CreatedTS    int64          `json:"created_ts"`
}

var defaultChecklistSeed = []TemplateItem{
	{Ref: "1.1", SectionNo: 1, SectionTitle: "Pre-Audit raccolta informazioni", Title: "Procurarsi e leggere i report relativi ai precedenti audit", GuidanceWhy: "Fornisce il quadro storico di vulnerabilit.", SeverityDefault: "osservazione", RequiresEvidence: true, SortOrder: 10},
	{Ref: "1.3", SectionNo: 1, SectionTitle: "Pre-Audit raccolta informazioni", Title: "Procurarsi lo schema logico di rete e connessioni", GuidanceWhy: "Prerequisito fondamentale per l'audit.", SeverityDefault: "alta", IsPrerequisite: true, RequiresEvidence: true, SortOrder: 30},
	{Ref: "1.6", SectionNo: 1, SectionTitle: "Pre-Audit raccolta informazioni", Title: "Verificare l'accesso ai LOG (Syslog / FortiAnalyzer / Cloud)", GuidanceWhy: "Senza log centralizzati non  possibile tracciare incidenti.", SeverityDefault: "alta", IsPrerequisite: true, RequiresEvidence: true, SortOrder: 60},
	{Ref: "1.7", SectionNo: 1, SectionTitle: "Pre-Audit raccolta informazioni", Title: "Controllare backup di configurazione e frequenza", GuidanceWhy: "Prerequisito critico per il ripristino.", SeverityDefault: "critica", IsPrerequisite: true, RequiresEvidence: true, SortOrder: 70},
	{Ref: "2.1", SectionNo: 2, SectionTitle: "Sicurezza fisica e ambiente operativo", Title: "Adeguatezza e sicurezza locali firewall", GuidanceWhy: "Condizioni ambientali avverse causano guasti.", SeverityDefault: "alta", SortOrder: 90},
	{Ref: "3.1", SectionNo: 3, SectionTitle: "Accessi amministrativi e log", Title: "Identificare utenti amministratori e reti permesse (Trusthosts)", GuidanceWhy: "Accesso amministrativo aperto espone a brute-force.", SeverityDefault: "critica", RequiresEvidence: true, SortOrder: 140},
	{Ref: "5.2", SectionNo: 5, SectionTitle: "Sistema operativo firewall", Title: "Verifica aggiornamento firmware e patch applicate", GuidanceWhy: "Firmware non aggiornati contengono falle note.", SeverityDefault: "critica", RequiresEvidence: true, SortOrder: 230},
	{Ref: "6.3", SectionNo: 6, SectionTitle: "Configurazione base e policy di sicurezza", Title: "Revisione policy con oggetti generici (ANY) in sorgente o destinazione", GuidanceWhy: "Regole permissive consentono traffico non autorizzato.", SeverityDefault: "alta", RequiresEvidence: true, SortOrder: 300},
}

func SeedDefaultTemplate(db *sql.DB) (int64, error) {
	var id int64
	err := db.QueryRow(`SELECT id FROM audit_templates WHERE version = 1`).Scan(&id)
	if err == nil {
		return id, nil
	}

	now := time.Now().Unix()
	res, err := db.Exec(
		`INSERT INTO audit_templates (version, name, status, created_ts, created_by, notes)
		 VALUES (1, 'Checklist Audit Manutenzione Firewall v1.0', 'published', ?, 'system', 'Template standard con controlli e soglie guida')`,
		now)
	if err != nil {
		return 0, err
	}
	templateID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for _, item := range defaultChecklistSeed {
		isPre := 0
		if item.IsPrerequisite {
			isPre = 1
		}
		reqEv := 0
		if item.RequiresEvidence {
			reqEv = 1
		}
		_, _ = db.Exec(
			`INSERT INTO audit_template_items (template_id, ref, section_no, section_title, title, guidance_why, severity_default, is_prerequisite, requires_evidence, sort_order)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			templateID, item.Ref, item.SectionNo, item.SectionTitle, item.Title, item.GuidanceWhy, item.SeverityDefault, isPre, reqEv, item.SortOrder)
	}

	return templateID, nil
}

func ListTemplates(db *sql.DB) ([]ChecklistTemplate, error) {
	rows, err := db.Query(
		`SELECT t.id, t.version, t.name, t.status, t.created_ts, t.created_by, COALESCE(t.notes, ''),
		        COUNT(i.id) AS item_count
		 FROM audit_templates t
		 LEFT JOIN audit_template_items i ON i.template_id = t.id
		 GROUP BY t.id ORDER BY t.version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ChecklistTemplate
	for rows.Next() {
		var t ChecklistTemplate
		if err := rows.Scan(&t.ID, &t.Version, &t.Name, &t.Status, &t.CreatedTS, &t.CreatedBy, &t.Notes, &t.ItemCount); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func GetTemplate(db *sql.DB, templateID int64) (*ChecklistTemplate, error) {
	var t ChecklistTemplate
	err := db.QueryRow(
		`SELECT id, version, name, status, created_ts, created_by, COALESCE(notes, '')
		 FROM audit_templates WHERE id = ?`, templateID).Scan(
		&t.ID, &t.Version, &t.Name, &t.Status, &t.CreatedTS, &t.CreatedBy, &t.Notes)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	rows, err := db.Query(
		`SELECT id, template_id, ref, section_no, section_title, title, COALESCE(guidance_why, ''),
		        COALESCE(guidance_good, ''), COALESCE(guidance_how, ''), COALESCE(thresholds_json, ''),
		        check_kind, severity_default, is_prerequisite, requires_evidence, sort_order
		 FROM audit_template_items WHERE template_id = ?
		 ORDER BY section_no ASC, sort_order ASC, ref ASC`, templateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item TemplateItem
		var isPre, reqEv int
		if err := rows.Scan(&item.ID, &item.TemplateID, &item.Ref, &item.SectionNo, &item.SectionTitle,
			&item.Title, &item.GuidanceWhy, &item.GuidanceGood, &item.GuidanceHow, &item.ThresholdsJSON,
			&item.CheckKind, &item.SeverityDefault, &isPre, &reqEv, &item.SortOrder); err != nil {
			return nil, err
		}
		item.IsPrerequisite = isPre == 1
		item.RequiresEvidence = reqEv == 1
		t.Items = append(t.Items, item)
	}
	t.ItemCount = len(t.Items)
	return &t, nil
}

func ListEngagements(db *sql.DB, status, tenant string) ([]Engagement, error) {
	query := `SELECT e.id, e.template_id, t.name, e.customer_name, COALESCE(e.tenant, ''),
	                 COALESCE(e.site_id, ''), e.created_ts, e.status, COALESCE(e.assigned_to, ''),
	                 COALESCE(e.scope_notes, ''), e.onsite_or_remote, COALESCE(e.interviewee, '')
	          FROM audit_engagements e
	          JOIN audit_templates t ON t.id = e.template_id
	          WHERE 1=1`
	var args []any
	if status != "" {
		query += ` AND e.status = ?`
		args = append(args, status)
	}
	if tenant != "" {
		query += ` AND e.tenant = ?`
		args = append(args, tenant)
	}
	query += ` ORDER BY e.created_ts DESC`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Engagement
	for rows.Next() {
		var e Engagement
		if err := rows.Scan(&e.ID, &e.TemplateID, &e.TemplateName, &e.CustomerName, &e.Tenant,
			&e.SiteID, &e.CreatedTS, &e.Status, &e.AssignedTo, &e.ScopeNotes, &e.OnsiteOrRemote, &e.Interviewee); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func CreateEngagement(db *sql.DB, customerName, tenant, siteID, assignedTo, scopeNotes, mode, interviewee string, templateID int64) (*Engagement, error) {
	if customerName == "" {
		return nil, fmt.Errorf("customer_name  obbligatorio")
	}
	if templateID <= 0 {
		tplID, err := SeedDefaultTemplate(db)
		if err != nil {
			return nil, err
		}
		templateID = tplID
	}
	if mode == "" {
		mode = "remote"
	}

	now := time.Now().Unix()
	res, err := db.Exec(
		`INSERT INTO audit_engagements (template_id, customer_name, tenant, site_id, created_ts, status, assigned_to, scope_notes, onsite_or_remote, interviewee)
		 VALUES (?, ?, ?, ?, ?, 'in_corso', ?, ?, ?, ?)`,
		templateID, customerName, tenant, siteID, now, assignedTo, scopeNotes, mode, interviewee)
	if err != nil {
		return nil, err
	}
	engID, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(
		`INSERT INTO audit_engagement_items (engagement_id, item_ref, status, severity, ai_assisted)
		 SELECT ?, ref, 'non_valutato', severity_default, 0
		 FROM audit_template_items WHERE template_id = ?`,
		engID, templateID)
	if err != nil {
		return nil, err
	}

	return GetEngagement(db, engID)
}

func GetEngagement(db *sql.DB, engagementID int64) (*Engagement, error) {
	var e Engagement
	err := db.QueryRow(
		`SELECT e.id, e.template_id, t.name, e.customer_name, COALESCE(e.tenant, ''),
		        COALESCE(e.site_id, ''), e.created_ts, e.status, COALESCE(e.assigned_to, ''),
		        COALESCE(e.scope_notes, ''), e.onsite_or_remote, COALESCE(e.interviewee, '')
		 FROM audit_engagements e
		 JOIN audit_templates t ON t.id = e.template_id
		 WHERE e.id = ?`, engagementID).Scan(
		&e.ID, &e.TemplateID, &e.TemplateName, &e.CustomerName, &e.Tenant,
		&e.SiteID, &e.CreatedTS, &e.Status, &e.AssignedTo, &e.ScopeNotes, &e.OnsiteOrRemote, &e.Interviewee)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	rows, err := db.Query(
		`SELECT ei.id, ei.engagement_id, ei.item_ref, ei.status, COALESCE(ei.severity, ''),
		        COALESCE(ei.finding_text, ''), COALESCE(ei.recommendation_text, ''), ei.ai_assisted,
		        ti.section_no, ti.section_title, ti.title, COALESCE(ti.guidance_why, ''),
		        COALESCE(ti.guidance_good, ''), COALESCE(ti.guidance_how, ''),
		        ti.is_prerequisite, ti.requires_evidence
		 FROM audit_engagement_items ei
		 JOIN audit_template_items ti ON ti.template_id = ? AND ti.ref = ei.item_ref
		 WHERE ei.engagement_id = ?
		 ORDER BY ti.section_no ASC, ti.sort_order ASC, ti.ref ASC`, e.TemplateID, engagementID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]int{
		"non_valutato": 0, "conforme": 0, "parziale": 0,
		"non_conforme": 0, "non_applicabile": 0, "da_verificare": 0,
	}

	for rows.Next() {
		var item EngagementItem
		var aiAss, isPre, reqEv int
		if err := rows.Scan(&item.ID, &item.EngagementID, &item.ItemRef, &item.Status, &item.Severity,
			&item.FindingText, &item.RecommendationText, &aiAss, &item.SectionNo, &item.SectionTitle,
			&item.Title, &item.GuidanceWhy, &item.GuidanceGood, &item.GuidanceHow, &isPre, &reqEv); err != nil {
			return nil, err
		}
		item.AIAssisted = aiAss == 1
		item.IsPrerequisite = isPre == 1
		item.RequiresEvidence = reqEv == 1
		e.Items = append(e.Items, item)
		stats[item.Status]++
	}
	e.Stats = stats
	return &e, nil
}

func UpdateItemAssessment(db *sql.DB, engagementID int64, itemRef, status, severity, finding, recommendation, actor string, aiAssisted bool) error {
	aiVal := 0
	if aiAssisted {
		aiVal = 1
	}
	res, err := db.Exec(
		`UPDATE audit_engagement_items
		 SET status = ?, severity = ?, finding_text = ?, recommendation_text = ?, ai_assisted = ?
		 WHERE engagement_id = ? AND item_ref = ?`,
		status, severity, finding, recommendation, aiVal, engagementID, itemRef)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return fmt.Errorf("item '%s' non trovato nell'engagement %d", itemRef, engagementID)
	}

	now := time.Now().Unix()
	_, _ = db.Exec(
		`INSERT INTO audit_engagement_history (engagement_id, item_ref, field_changed, new_value, changed_by, changed_ts)
		 VALUES (?, ?, 'status', ?, ?, ?)`,
		engagementID, itemRef, status, actor, now)
	return nil
}

func AddEvidence(db *sql.DB, engagementID int64, itemRef, kind, filename, path string, payload map[string]any, confidential bool) (int64, error) {
	pJSON, _ := json.Marshal(payload)
	confVal := 0
	if confidential {
		confVal = 1
	}
	now := time.Now().Unix()
	res, err := db.Exec(
		`INSERT INTO audit_evidence (engagement_id, item_ref, kind, filename, path, payload_json, confidential, created_ts)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		engagementID, itemRef, kind, filename, path, string(pJSON), confVal, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func GenerateAuditReportHTML(db *sql.DB, engagementID int64) (string, error) {
	eng, err := GetEngagement(db, engagementID)
	if err != nil || eng == nil {
		return "", fmt.Errorf("engagement non trovato")
	}

	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><meta charset='utf-8'><title>Relazione Audit - ")
	sb.WriteString(eng.CustomerName)
	sb.WriteString("</title><style>body{font-family:Segoe UI,sans-serif;margin:40px;color:#222;}table{width:100%;border-collapse:collapse;margin-top:20px;}th,td{border:1px solid #ccc;padding:8px;text-align:left;}th{background:#f4f4f4;}.badge{padding:4px 8px;border-radius:4px;font-size:12px;}.conforme{background:#d4edda;color:#155724;}.non_conforme{background:#f8d7da;color:#721c24;}</style></head><body>")
	sb.WriteString(fmt.Sprintf("<h1>Relazione Audit di Sicurezza: %s</h1>", eng.CustomerName))
	sb.WriteString(fmt.Sprintf("<p><strong>Data:</strong> %s | <strong>Modalit:</strong> %s | <strong>Stato:</strong> %s</p>",
		time.Unix(eng.CreatedTS, 0).Format("2006-01-02"), eng.OnsiteOrRemote, eng.Status))
	sb.WriteString("<h2>Dettaglio Verifiche</h2><table><thead><tr><th>Ref</th><th>Sezione</th><th>Controllo</th><th>Esito</th><th>Gravit</th><th>Note / Evidenze</th></tr></thead><tbody>")

	for _, it := range eng.Items {
		sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td><span class='badge %s'>%s</span></td><td>%s</td><td>%s</td></tr>",
			it.ItemRef, it.SectionTitle, it.Title, it.Status, it.Status, it.Severity, it.FindingText))
	}
	sb.WriteString("</tbody></table></body></html>")
	return sb.String(), nil
}
