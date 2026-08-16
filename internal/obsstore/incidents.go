package obsstore

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/rules"
)

type Incident struct {
	ID             int64          `json:"id"`
	Tenant         string         `json:"tenant"`
	EntityKey      string         `json:"entity_key"`
	OpenedTS       int64          `json:"opened_ts"`
	LastEventTS    int64          `json:"last_event_ts"`
	ClosedTS       *int64         `json:"closed_ts,omitempty"`
	Title          string         `json:"title"`
	Severity       int            `json:"severity"`
	EventCount     int            `json:"event_count"`
	Status         string         `json:"status"`
	CauseKind      string         `json:"cause_kind"`
	Confidence     int            `json:"confidence"`
	ReasoningJSON  string         `json:"reasoning_json,omitempty"`
	Reasoning      map[string]any `json:"reasoning,omitempty"`
	AINarrative    string         `json:"ai_narrative,omitempty"`
	AINarrativeTS  *int64         `json:"ai_narrative_ts,omitempty"`
	AIAssisted     int            `json:"ai_assisted"`
}

type EvidenceRow struct {
	ID                    int64          `json:"id"`
	CreatedTS             int64          `json:"created_ts"`
	TS                    int64          `json:"ts"`
	Tenant                string         `json:"tenant"`
	IncidentID            *int64         `json:"incident_id,omitempty"`
	EventID               *int64         `json:"event_id,omitempty"`
	EntityKey             string         `json:"entity_key"`
	Role                  string         `json:"role"`
	RuleID                string         `json:"rule_id"`
	RuleVersion           string         `json:"rule_version"`
	ParamsJSON            string         `json:"params_json"`
	Weight                int            `json:"weight"`
	Severity              *int           `json:"severity,omitempty"`
	SrcIP                 string         `json:"src_ip,omitempty"`
	DstIP                 string         `json:"dst_ip,omitempty"`
	SwitchPort            string         `json:"switch_port,omitempty"`
	Summary               string         `json:"summary"`
	AttrsJSON             string         `json:"attrs_json"`
	DedupKey              string         `json:"dedup_key,omitempty"`
	Status                string         `json:"status"`
	RetractedByEvidenceID *int64         `json:"retracted_by_evidence_id,omitempty"`
	RetractedByRuleID     string         `json:"retracted_by_rule_id,omitempty"`
	RetractedAt           *int64         `json:"retracted_at,omitempty"`
	RetractedReason       string         `json:"retracted_reason,omitempty"`
}

type IncidentConclusion struct {
	ID            int64          `json:"id"`
	IncidentID    int64          `json:"incident_id"`
	ConcludedTS   int64          `json:"concluded_ts"`
	CauseKind     string         `json:"cause_kind"`
	Confidence    int            `json:"confidence"`
	ReasoningJSON string         `json:"reasoning_json,omitempty"`
	Reasoning     map[string]any `json:"reasoning,omitempty"`
	SupersededTS  *int64         `json:"superseded_ts,omitempty"`
}

const (
	GapSeconds        = 900  // 15 minuti di gap
	QuietSeconds      = 1800 // 30 minuti di quiete
	LookbackSeconds   = 3600
	ConfidenceStep    = 8
	ConfidenceMax     = 95
)

// ListIncidents elenca gli incidenti paginati e filtrati per finestra, stato e tenant.
func (s *Store) ListIncidents(cutoff int64, status string, tenants []string, limit, offset int) ([]Incident, error) {
	query := `SELECT id, tenant, entity_key, opened_ts, last_event_ts, closed_ts,
	                 title, severity, event_count, status, COALESCE(cause_kind, ''), COALESCE(confidence, 0),
	                 ai_assisted
	          FROM incidents
	          WHERE last_event_ts >= ?`
	args := []any{cutoff}

	if status != "" && status != "all" {
		query += ` AND status = ?`
		args = append(args, status)
	}

	if tenants != nil {
		if len(tenants) == 0 {
			return []Incident{}, nil
		}
		placeholders := ""
		for i, t := range tenants {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, t)
		}
		query += fmt.Sprintf(` AND tenant IN (%s)`, placeholders)
	}

	query += ` ORDER BY last_event_ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Incident
	for rows.Next() {
		var inc Incident
		var closedTS *int64
		if err := rows.Scan(
			&inc.ID, &inc.Tenant, &inc.EntityKey, &inc.OpenedTS, &inc.LastEventTS, &closedTS,
			&inc.Title, &inc.Severity, &inc.EventCount, &inc.Status, &inc.CauseKind, &inc.Confidence,
			&inc.AIAssisted,
		); err != nil {
			return nil, err
		}
		inc.ClosedTS = closedTS
		out = append(out, inc)
	}
	return out, nil
}

// GetIncident ritorna il dettaglio di un incidente.
func (s *Store) GetIncident(id int64) (*Incident, error) {
	row := s.DB.QueryRow(
		`SELECT id, tenant, entity_key, opened_ts, last_event_ts, closed_ts,
		        title, severity, event_count, status, COALESCE(cause_kind, ''), COALESCE(confidence, 0),
		        COALESCE(reasoning_json, '{}'), COALESCE(ai_narrative, ''), ai_narrative_ts, ai_assisted
		 FROM incidents WHERE id = ?`, id)

	var inc Incident
	var closedTS, aiTS *int64
	if err := row.Scan(
		&inc.ID, &inc.Tenant, &inc.EntityKey, &inc.OpenedTS, &inc.LastEventTS, &closedTS,
		&inc.Title, &inc.Severity, &inc.EventCount, &inc.Status, &inc.CauseKind, &inc.Confidence,
		&inc.ReasoningJSON, &inc.AINarrative, &aiTS, &inc.AIAssisted,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	inc.ClosedTS = closedTS
	inc.AINarrativeTS = aiTS
	_ = json.Unmarshal([]byte(inc.ReasoningJSON), &inc.Reasoning)
	return &inc, nil
}

// UpdateIncidentStatus esegue una transizione di stato con controllo di concorrenza.
func (s *Store) UpdateIncidentStatus(id int64, fromStatus, toStatus string) (bool, error) {
	res, err := s.DB.Exec(
		`UPDATE incidents SET status = ? WHERE id = ? AND status = ?`,
		toStatus, id, fromStatus)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// SaveAINarrative aggiorna la narrativa AI di un incidente.
func (s *Store) SaveAINarrative(id int64, narrative string, now int64) error {
	_, err := s.DB.Exec(
		`UPDATE incidents SET ai_narrative = ?, ai_narrative_ts = ?, ai_assisted = 1 WHERE id = ?`,
		narrative, now, id)
	return err
}

// PreviousConclusions ritorna lo storico delle conclusioni per un incidente.
func (s *Store) PreviousConclusions(incidentID int64) ([]IncidentConclusion, error) {
	rows, err := s.DB.Query(
		`SELECT id, incident_id, concluded_ts, cause_kind, confidence, reasoning_json, superseded_ts
		 FROM incident_conclusions
		 WHERE incident_id = ? AND superseded_ts IS NOT NULL
		 ORDER BY concluded_ts DESC LIMIT 20`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IncidentConclusion
	for rows.Next() {
		var c IncidentConclusion
		var rJSON string
		if err := rows.Scan(&c.ID, &c.IncidentID, &c.ConcludedTS, &c.CauseKind, &c.Confidence, &rJSON, &c.SupersededTS); err != nil {
			return nil, err
		}
		c.ReasoningJSON = rJSON
		_ = json.Unmarshal([]byte(rJSON), &c.Reasoning)
		out = append(out, c)
	}
	return out, nil
}

// ActiveTriggerEndpoints ritorna src_ip e dst_ip del trigger attivo di un incidente.
func (s *Store) ActiveTriggerEndpoints(incidentID int64) (srcIP, dstIP string, err error) {
	row := s.DB.QueryRow(
		`SELECT COALESCE(src_ip, ''), COALESCE(dst_ip, '')
		 FROM evidence
		 WHERE incident_id = ? AND status = 'active' AND role = 'trigger' AND src_ip IS NOT NULL AND src_ip != ''
		 ORDER BY ts ASC, id ASC LIMIT 1`, incidentID)
	err = row.Scan(&srcIP, &dstIP)
	if err == sql.ErrNoRows {
		return "", "", nil
	}
	return srcIP, dstIP, err
}

// GroupAndReasonIncidents raggruppa evidenze aperte e calcola conclusioni.
func (s *Store) GroupAndReasonIncidents(now int64, overrides map[string]any) (int, error) {
	if now == 0 {
		now = time.Now().Unix()
	}

	rows, err := s.DB.Query(
		`SELECT id, ts, tenant, entity_key, role, rule_id, severity
		 FROM evidence
		 WHERE incident_id IS NULL AND status = 'active' AND created_ts >= ?
		 ORDER BY ts ASC, id ASC`, now-LookbackSeconds)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type unassigned struct {
		id       int64
		ts       int64
		tenant   string
		entity   string
		role     string
		ruleID   string
		severity int
	}
	var unassignedList []unassigned
	for rows.Next() {
		var u unassigned
		var sev sql.NullInt64
		if err := rows.Scan(&u.id, &u.ts, &u.tenant, &u.entity, &u.role, &u.ruleID, &sev); err != nil {
			return 0, err
		}
		if sev.Valid {
			u.severity = int(sev.Int64)
		} else {
			u.severity = 4
		}
		if u.entity != "" {
			unassignedList = append(unassignedList, u)
		}
	}
	rows.Close()

	touched := map[int64]bool{}
	linked := 0

	for _, u := range unassignedList {
		var incidentID int64
		err := s.DB.QueryRow(
			`SELECT id FROM incidents
			 WHERE tenant = ? AND closed_ts IS NULL AND entity_key = ? AND last_event_ts >= ?
			 ORDER BY opened_ts ASC, id ASC LIMIT 1`,
			u.tenant, u.entity, u.ts-GapSeconds).Scan(&incidentID)

		if err == sql.ErrNoRows {
			title := u.entity
			if idx := len("ip:"); len(u.entity) > idx && u.entity[:idx] == "ip:" {
				title = u.entity[idx:]
			}
			res, err := s.DB.Exec(
				`INSERT INTO incidents (tenant, entity_key, opened_ts, last_event_ts, title, severity, event_count, status)
				 VALUES (?, ?, ?, ?, ?, ?, 0, 'new')`,
				u.tenant, u.entity, u.ts, u.ts, title, u.severity)
			if err != nil {
				return linked, err
			}
			incidentID, _ = res.LastInsertId()
		} else if err != nil {
			return linked, err
		}

		if _, err := s.DB.Exec(`UPDATE evidence SET incident_id = ? WHERE id = ?`, incidentID, u.id); err != nil {
			return linked, err
		}
		if _, err := s.DB.Exec(
			`UPDATE incidents
			 SET last_event_ts = MAX(last_event_ts, ?),
			     opened_ts = MIN(opened_ts, ?),
			     event_count = event_count + 1,
			     severity = MIN(COALESCE(severity, ?), ?)
			 WHERE id = ?`,
			u.ts, u.ts, u.severity, u.severity, incidentID); err != nil {
			return linked, err
		}
		touched[incidentID] = true
		linked++
	}

	// Incidenti con evidenze ritrattate di recente
	retRows, err := s.DB.Query(
		`SELECT DISTINCT incident_id FROM evidence
		 WHERE status = 'retracted' AND incident_id IS NOT NULL AND retracted_at >= ?`, now-LookbackSeconds)
	if err == nil {
		for retRows.Next() {
			var iID int64
			if err := retRows.Scan(&iID); err == nil {
				touched[iID] = true
			}
		}
		retRows.Close()
	}

	for id := range touched {
		s.reasonIncident(id, overrides)
	}

	return linked, nil
}

func (s *Store) reasonIncident(incidentID int64, overrides map[string]any) {
	inc, err := s.GetIncident(incidentID)
	if err != nil || inc == nil {
		return
	}

	evRows, err := s.DB.Query(
		`SELECT id, ts, role, rule_id, rule_version, params_json, severity,
		        COALESCE(src_ip, ''), COALESCE(dst_ip, ''), COALESCE(switch_port, ''), summary
		 FROM evidence WHERE incident_id = ? AND status = 'active'
		 ORDER BY ts ASC, id ASC`, incidentID)
	if err != nil {
		return
	}
	defer evRows.Close()

	var activeEvidence []EvidenceRow
	for evRows.Next() {
		var e EvidenceRow
		var sev sql.NullInt64
		if err := evRows.Scan(&e.ID, &e.TS, &e.Role, &e.RuleID, &e.RuleVersion, &e.ParamsJSON, &sev,
			&e.SrcIP, &e.DstIP, &e.SwitchPort, &e.Summary); err != nil {
			continue
		}
		if sev.Valid {
			sInt := int(sev.Int64)
			e.Severity = &sInt
		}
		activeEvidence = append(activeEvidence, e)
	}
	evRows.Close()

	if len(activeEvidence) == 0 {
		return
	}

	var trigger *EvidenceRow
	for i := range activeEvidence {
		e := &activeEvidence[i]
		if e.Role == "trigger" {
			if trigger == nil {
				trigger = e
			} else {
				tSev := 9
				if trigger.Severity != nil {
					tSev = *trigger.Severity
				}
				eSev := 9
				if e.Severity != nil {
					eSev = *e.Severity
				}
				if eSev < tSev || (eSev == tSev && (e.TS < trigger.TS || (e.TS == trigger.TS && e.ID < trigger.ID))) {
					trigger = e
				}
			}
		}
	}

	cause := "causa_non_determinata"
	base := 25
	ruleVersion := "-"
	var params map[string]any

	if trigger != nil {
		cause = trigger.RuleID
		ruleVersion = trigger.RuleVersion
		_ = json.Unmarshal([]byte(trigger.ParamsJSON), &params)
		if r, ok := rules.Rules[cause]; ok {
			base = r.BaseConfidence
		}
	}

	roles := map[string]bool{}
	ruleIDs := map[string]bool{}
	var sources []string

	for _, e := range activeEvidence {
		roles[e.Role] = true
		ruleIDs[e.RuleID] = true
	}
	if roles["supporting"] {
		sources = append(sources, "evidenza_di_supporto")
	}
	if roles["symptom"] {
		sources = append(sources, "sintomo_osservato")
	}
	if roles["consequence"] {
		sources = append(sources, "conseguenza_osservata")
	}
	if len(ruleIDs) > 1 {
		sources = append(sources, "piu_regole_concordi")
	}
	for _, e := range activeEvidence {
		if e.SwitchPort != "" {
			sources = append(sources, "posizione_fisica")
			break
		}
	}

	confidence := base + ConfidenceStep*len(sources)
	if confidence > ConfidenceMax {
		confidence = ConfidenceMax
	}

	byRole := map[string][]int64{}
	for _, e := range activeEvidence {
		byRole[e.Role] = append(byRole[e.Role], e.ID)
	}

	reasoningMap := map[string]any{
		"cause":         cause,
		"rule_id":       cause,
		"rule_version":  ruleVersion,
		"rule_params":   params,
		"confidence":    confidence,
		"sources_used":  sources,
		"rules_fired":   ruleIDsKeys(ruleIDs),
		"evidence_refs": byRole,
	}
	reasoningJSON, _ := json.Marshal(reasoningMap)

	now := time.Now().Unix()
	s.DB.Exec(
		`UPDATE incident_conclusions SET superseded_ts = ? WHERE incident_id = ? AND superseded_ts IS NULL`,
		now, incidentID)

	s.DB.Exec(
		`INSERT INTO incident_conclusions (incident_id, concluded_ts, cause_kind, confidence, reasoning_json)
		 VALUES (?, ?, ?, ?, ?)`,
		incidentID, now, cause, confidence, string(reasoningJSON))

	s.DB.Exec(
		`UPDATE incidents SET cause_kind = ?, confidence = ?, reasoning_json = ? WHERE id = ?`,
		cause, confidence, string(reasoningJSON), incidentID)
}

func ruleIDsKeys(m map[string]bool) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
