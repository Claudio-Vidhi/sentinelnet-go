package obsstore

import (
	"database/sql"
	"errors"
	"strings"
)

// MaxLimit e MaxWindow limitano le query esposte via API.
const (
	MaxLimit  = 500
	MaxWindow = 7 * 86400 // 7 giorni
)

// tenantClause costruisce il filtro multi-tenant.
//
// I placeholder sono sempre parametri bound, mai interpolazione di stringhe:
// il tenant arriva dal profilo utente ma la regola vale comunque, perché è
// l'unica barriera fra i dati di tenant diversi.
// scope nil = nessuna restrizione (admin).
func tenantClause(scope []string) (string, []any) {
	if scope == nil {
		return "", nil
	}
	if len(scope) == 0 {
		return " AND 1=0", nil // nessun tenant visibile: nessuna riga
	}
	args := make([]any, 0, len(scope))
	for _, t := range scope {
		args = append(args, t)
	}
	return " AND tenant IN (" + placeholders(len(scope)) + ")", args
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// TopFlow è una riga di /api/observability/top.
type TopFlow struct {
	Tenant       string `json:"tenant"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	Protocol     *int   `json:"protocol"`
	DstPort      *int   `json:"dst_port"`
	Source       string `json:"source"`
	TotalBytes   int64  `json:"total_bytes"`
	TotalPackets int64  `json:"total_packets"`
	FlowCount    int64  `json:"flow_count"`
}

// TopFlows aggrega i flussi della finestra richiesta.
// metric: "bytes" | "packets". source: "all" | ipfix | netflow | sflow.
func (s *Store) TopFlows(cutoff int64, scope []string, metric, source string, limit int) ([]TopFlow, error) {
	orderCol := "total_bytes"
	if metric == "packets" {
		orderCol = "total_packets"
	}
	clause, args := tenantClause(scope)
	params := append([]any{cutoff}, args...)

	sourceClause := ""
	if source != "" && source != "all" {
		sourceClause = " AND source = ?"
		params = append(params, source)
	}
	params = append(params, limit)

	rows, err := s.DB.Query(`
		SELECT tenant, src_ip, dst_ip, protocol, dst_port, COALESCE(source,''),
		       SUM(total_bytes), SUM(total_packets), SUM(flow_count)
		FROM flow_aggregates
		WHERE window_start >= ?`+clause+sourceClause+`
		GROUP BY tenant, src_ip, dst_ip, protocol, dst_port, source
		ORDER BY SUM(`+orderCol+`) DESC
		LIMIT ?`, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TopFlow{}
	for rows.Next() {
		var f TopFlow
		var proto, port sql.NullInt64
		if err := rows.Scan(&f.Tenant, &f.SrcIP, &f.DstIP, &proto, &port, &f.Source,
			&f.TotalBytes, &f.TotalPackets, &f.FlowCount); err != nil {
			return nil, err
		}
		f.Protocol, f.DstPort = nullInt(proto), nullInt(port)
		out = append(out, f)
	}
	return out, rows.Err()
}

// SyslogRow è una riga di /api/observability/syslog.
type SyslogRow struct {
	TS         int64  `json:"ts"`
	Tenant     string `json:"tenant"`
	DeviceIP   string `json:"device_ip"`
	Severity   *int   `json:"severity"`
	Action     string `json:"action"`
	Message    string `json:"message"`
	ExporterIP string `json:"exporter_ip"`
}

func (s *Store) SyslogEvents(cutoff int64, scope []string, limit int) ([]SyslogRow, error) {
	clause, args := tenantClause(scope)
	params := append([]any{cutoff}, args...)
	params = append(params, limit)

	rows, err := s.DB.Query(`
		SELECT ts, tenant, COALESCE(device_ip,''), severity, COALESCE(action,''),
		       COALESCE(message,''), COALESCE(exporter_ip,'')
		FROM syslog_events
		WHERE ts >= ?`+clause+`
		ORDER BY ts DESC
		LIMIT ?`, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SyslogRow{}
	for rows.Next() {
		var r SyslogRow
		var sev sql.NullInt64
		if err := rows.Scan(&r.TS, &r.Tenant, &r.DeviceIP, &sev, &r.Action,
			&r.Message, &r.ExporterIP); err != nil {
			return nil, err
		}
		r.Severity = nullInt(sev)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Anomaly è una riga di /api/observability/anomalies.
type Anomaly struct {
	ID           int64  `json:"id"`
	CreatedTS    int64  `json:"created_ts"`
	Tenant       string `json:"tenant"`
	Kind         string `json:"kind"`
	SrcIP        string `json:"src_ip"`
	DstIP        string `json:"dst_ip"`
	SwitchPort   string `json:"switch_port"`
	Severity     *int   `json:"severity"`
	Status       string `json:"status"`
	EvidenceJSON string `json:"evidence_json"`
}

func (s *Store) Anomalies(cutoff int64, scope []string, status string, limit, page int) ([]Anomaly, error) {
	clause, args := tenantClause(scope)
	params := append([]any{cutoff}, args...)
	statusClause := ""
	if status != "" && status != "all" {
		statusClause = " AND status = ?"
		params = append(params, status)
	}
	params = append(params, limit, page*limit)

	rows, err := s.DB.Query(`
		SELECT id, created_ts, tenant, COALESCE(kind,''), COALESCE(src_ip,''),
		       COALESCE(dst_ip,''), COALESCE(switch_port,''), severity, status,
		       COALESCE(evidence_json,'')
		FROM correlated_events
		WHERE created_ts >= ?`+clause+statusClause+`
		ORDER BY created_ts DESC
		LIMIT ? OFFSET ?`, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Anomaly{}
	for rows.Next() {
		var a Anomaly
		var sev sql.NullInt64
		if err := rows.Scan(&a.ID, &a.CreatedTS, &a.Tenant, &a.Kind, &a.SrcIP,
			&a.DstIP, &a.SwitchPort, &sev, &a.Status, &a.EvidenceJSON); err != nil {
			return nil, err
		}
		a.Severity = nullInt(sev)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Errori di transizione di stato di un'anomalia.
var (
	ErrAnomalyNotFound = errors.New("evento non trovato")
	ErrAnomalyStale    = errors.New("lo stato dell'evento è cambiato nel frattempo")
)

// TransitionAnomaly cambia lo stato di un evento correlato.
//
// La UPDATE include lo stato di partenza (concorrenza ottimistica): se due
// operatori agiscono insieme, il secondo riceve un errore invece di
// sovrascrivere silenziosamente la decisione del primo.
//
// Un evento fuori dallo scope del chiamante ritorna lo stesso errore di uno
// inesistente, per non confermarne l'esistenza.
func (s *Store) TransitionAnomaly(id int64, from, to string, scope []string) error {
	var tenant, current string
	err := s.DB.QueryRow(`SELECT tenant, status FROM correlated_events WHERE id = ?`, id).
		Scan(&tenant, &current)
	if err == sql.ErrNoRows {
		return ErrAnomalyNotFound
	}
	if err != nil {
		return err
	}
	if scope != nil && !containsString(scope, tenant) {
		return ErrAnomalyNotFound
	}
	res, err := s.DB.Exec(`UPDATE correlated_events SET status = ? WHERE id = ? AND status = ?`,
		to, id, from)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrAnomalyStale
	}
	return nil
}

// APIObservation è una riga di /api/observability/api-context.
type APIObservation struct {
	TS          int64  `json:"ts"`
	Tenant      string `json:"tenant"`
	DeviceIP    string `json:"device_ip"`
	Kind        string `json:"kind"`
	SummaryJSON string `json:"summary_json"`
}

// APIContext ritorna l'ultima osservazione per ciascun kind di un device.
func (s *Store) APIContext(deviceIP string, scope []string) ([]APIObservation, error) {
	clause, args := tenantClause(scope)
	params := append([]any{deviceIP}, args...)
	params = append(params, deviceIP)

	rows, err := s.DB.Query(`
		SELECT ts, tenant, device_ip, kind, summary_json
		FROM api_observations
		WHERE device_ip = ?`+clause+`
		  AND id IN (SELECT MAX(id) FROM api_observations WHERE device_ip = ? GROUP BY kind)
		ORDER BY kind`, params...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []APIObservation{}
	for rows.Next() {
		var o APIObservation
		if err := rows.Scan(&o.TS, &o.Tenant, &o.DeviceIP, &o.Kind, &o.SummaryJSON); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func nullInt(v sql.NullInt64) *int {
	if !v.Valid {
		return nil
	}
	n := int(v.Int64)
	return &n
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
