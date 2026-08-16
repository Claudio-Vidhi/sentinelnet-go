// Package timeline: unione multi-fonte cronologica per il dettaglio di un incidente.
// Porta di observability/timeline.py.
package timeline

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/endpoints"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

type Entry struct {
	TS       int64          `json:"ts"`
	Source   string         `json:"source"`
	Role     string         `json:"role,omitempty"`
	Severity *int           `json:"severity,omitempty"`
	Text     string         `json:"text"`
	Status   string         `json:"status,omitempty"`
	Ref      map[string]any `json:"ref,omitempty"`
}

const (
	PadSeconds     = 300
	MaxSyslog      = 200
	MaxFlowBuckets = 200
	MaxAPI         = 50
)

func humanBytes(n int64) string {
	val := float64(n)
	for _, unit := range []string{"B", "KB", "MB", "GB"} {
		if val < 1024 || unit == "GB" {
			if unit == "B" {
				return fmt.Sprintf("%.0f B", val)
			}
			return fmt.Sprintf("%.1f %s", val, unit)
		}
		val /= 1024.0
	}
	return fmt.Sprintf("%.1f GB", val)
}

// Build costruisce la timeline multi-fonte per un incidente.
func Build(obsDB *sql.DB, st *store.Store, incidentID int64) ([]Entry, error) {
	var tenant string
	var openedTS, lastEventTS int64
	err := obsDB.QueryRow(
		`SELECT tenant, opened_ts, last_event_ts FROM incidents WHERE id = ?`, incidentID).Scan(
		&tenant, &openedTS, &lastEventTS)
	if err != nil {
		if err == sql.ErrNoRows {
			return []Entry{}, nil
		}
		return nil, err
	}

	frm := openedTS - PadSeconds
	to := lastEventTS + PadSeconds

	evRows, err := obsDB.Query(
		`SELECT id, ts, role, rule_id, rule_version, COALESCE(params_json, '{}'), severity,
		        COALESCE(src_ip, ''), COALESCE(dst_ip, ''), COALESCE(switch_port, ''), summary,
		        COALESCE(attrs_json, '{}'), event_id, status, retracted_by_evidence_id,
		        COALESCE(retracted_by_rule_id, ''), retracted_at, COALESCE(retracted_reason, '')
		 FROM evidence WHERE incident_id = ?
		 ORDER BY ts ASC, id ASC`, incidentID)
	if err != nil {
		return nil, err
	}
	defer evRows.Close()

	var entries []Entry
	ipsMap := map[string]bool{}

	for evRows.Next() {
		var id, ts int64
		var role, ruleID, ruleVersion, paramsJSON, summary, attrsJSON, status, retRuleID, retReason string
		var sev sql.NullInt64
		var srcIP, dstIP, switchPort string
		var eventID, retEvID, retAt sql.NullInt64

		if err := evRows.Scan(&id, &ts, &role, &ruleID, &ruleVersion, &paramsJSON, &sev,
			&srcIP, &dstIP, &switchPort, &summary, &attrsJSON, &eventID, &status,
			&retEvID, &retRuleID, &retAt, &retReason); err != nil {
			continue
		}

		if srcIP != "" {
			ipsMap[srcIP] = true
		}
		if dstIP != "" {
			ipsMap[dstIP] = true
		}

		detail := summary
		if switchPort != "" {
			detail += fmt.Sprintf(" (%s)", switchPort)
		}

		var paramsMap, attrsMap map[string]any
		_ = json.Unmarshal([]byte(paramsJSON), &paramsMap)
		_ = json.Unmarshal([]byte(attrsJSON), &attrsMap)

		ref := map[string]any{
			"evidence_id":  id,
			"rule_id":      ruleID,
			"rule_version": ruleVersion,
			"rule_params":  paramsMap,
			"attrs":        attrsMap,
		}
		if eventID.Valid {
			ref["event_id"] = eventID.Int64
		}
		if retEvID.Valid {
			ref["retracted_by_evidence_id"] = retEvID.Int64
		}
		if retRuleID != "" {
			ref["retracted_by_rule_id"] = retRuleID
		}
		if retAt.Valid {
			ref["retracted_at"] = retAt.Int64
		}
		if retReason != "" {
			ref["retracted_reason"] = retReason
		}

		var sevPtr *int
		if sev.Valid {
			s := int(sev.Int64)
			sevPtr = &s
		}

		entries = append(entries, Entry{
			TS:       ts,
			Source:   "evidence",
			Role:     role,
			Severity: sevPtr,
			Text:     detail,
			Status:   status,
			Ref:      ref,
		})
	}
	evRows.Close()

	var ipList []string
	for ip := range ipsMap {
		ipList = append(ipList, ip)
	}
	sort.Strings(ipList)

	if len(ipList) > 0 {
		entries = append(entries, syslogEntries(obsDB, tenant, ipList, frm, to)...)
		entries = append(entries, flowEntries(obsDB, tenant, ipList, frm, to)...)
		entries = append(entries, apiEntries(obsDB, tenant, ipList, frm, to)...)
		if st != nil {
			entries = append(entries, locationEntries(st, tenant, ipList)...)
		}
		entries = append(entries, endpointEntries(ipList)...)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].TS < entries[j].TS
	})

	return entries, nil
}

func syslogEntries(db *sql.DB, tenant string, ips []string, frm, to int64) []Entry {
	var out []Entry
	query := `SELECT ts, device_ip, severity, action, message
	          FROM syslog_events
	          WHERE tenant = ? AND ts BETWEEN ? AND ?`
	args := []any{tenant, frm, to}

	placeholders := ""
	for i, ip := range ips {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, ip)
	}
	query += fmt.Sprintf(` AND device_ip IN (%s) ORDER BY ts ASC LIMIT ?`, placeholders)
	args = append(args, MaxSyslog)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var ts int64
		var devIP, act, msg string
		var sev sql.NullInt64
		if err := rows.Scan(&ts, &devIP, &sev, &act, &msg); err != nil {
			continue
		}
		var sevPtr *int
		if sev.Valid {
			s := int(sev.Int64)
			sevPtr = &s
		}
		text := msg
		if len(text) > 300 {
			text = text[:300]
		}
		out = append(out, Entry{
			TS:       ts,
			Source:   "syslog",
			Severity: sevPtr,
			Text:     text,
			Ref:      map[string]any{"device_ip": devIP, "action": act},
		})
	}
	return out
}

func flowEntries(db *sql.DB, tenant string, ips []string, frm, to int64) []Entry {
	var out []Entry
	placeholders := ""
	var args []any
	args = append(args, tenant, frm, to)
	for i, ip := range ips {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, ip)
	}
	for _, ip := range ips {
		args = append(args, ip)
	}
	query := fmt.Sprintf(
		`SELECT window_start, SUM(total_bytes) AS total_bytes, SUM(total_packets) AS total_packets, COUNT(*) AS pairs
		 FROM flow_aggregates
		 WHERE tenant = ? AND window_start BETWEEN ? AND ?
		   AND (src_ip IN (%s) OR dst_ip IN (%s))
		 GROUP BY window_start
		 ORDER BY window_start ASC LIMIT ?`, placeholders, placeholders)
	args = append(args, MaxFlowBuckets)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var wStart, totalBytes, totalPkts, pairs int64
		if err := rows.Scan(&wStart, &totalBytes, &totalPkts, &pairs); err != nil {
			continue
		}
		out = append(out, Entry{
			TS:     wStart,
			Source: "flow",
			Text:   fmt.Sprintf("%s in %d flussi", humanBytes(totalBytes), pairs),
			Ref:    map[string]any{"bytes": totalBytes, "packets": totalPkts},
		})
	}
	return out
}

func apiEntries(db *sql.DB, tenant string, ips []string, frm, to int64) []Entry {
	var out []Entry
	placeholders := ""
	var args []any
	args = append(args, tenant, frm, to)
	for i, ip := range ips {
		if i > 0 {
			placeholders += ","
		}
		placeholders += "?"
		args = append(args, ip)
	}
	query := fmt.Sprintf(
		`SELECT ts, device_ip, kind, summary_json
		 FROM api_observations
		 WHERE tenant = ? AND ts BETWEEN ? AND ? AND device_ip IN (%s)
		 ORDER BY ts ASC LIMIT ?`, placeholders)
	args = append(args, MaxAPI)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var ts int64
		var devIP, kind, summary string
		if err := rows.Scan(&ts, &devIP, &kind, &summary); err != nil {
			continue
		}
		if len(summary) > 500 {
			summary = summary[:500]
		}
		out = append(out, Entry{
			TS:     ts,
			Source: "api",
			Text:   fmt.Sprintf("snapshot %s da %s", kind, devIP),
			Ref:    map[string]any{"device_ip": devIP, "kind": kind, "summary": summary},
		})
	}
	return out
}

func locationEntries(st *store.Store, tenant string, ips []string) []Entry {
	var out []Entry
	for _, ip := range ips {
		rows, err := st.ClientMap("", ip, "", []string{tenant}, 5)
		if err != nil {
			continue
		}
		for _, r := range rows {
			var ts int64
			tStr := r.PortLastSeen
			if tStr == "" && r.ARPEntry != nil {
				tStr = r.LastSeen
			}
			if t, err := time.Parse(time.RFC3339, tStr); err == nil {
				ts = t.Unix()
			} else if t, err := time.Parse("2006-01-02 15:04:05", tStr); err == nil {
				ts = t.Unix()
			}
			if ts == 0 {
				continue
			}
			where := r.SwitchName
			if where == "" {
				where = r.SwitchIP
			}
			out = append(out, Entry{
				TS:     ts,
				Source: "location",
				Text:   fmt.Sprintf("%s (%s) su %s:%s, VLAN %s", ip, endpoints.DescribeMAC(r.MAC), where, r.SwitchPort, r.PortVLAN),
				Ref: map[string]any{
					"mac":             r.MAC,
					"switch_ip":       r.SwitchIP,
					"switch_port":     r.SwitchPort,
					"vlan":            r.PortVLAN,
					"stable_identity": endpoints.IsStableIdentity(r.MAC),
					"mac_info":        endpoints.ClassifyMAC(r.MAC),
				},
			})
		}
	}
	return out
}

func endpointEntries(ips []string) []Entry {
	var out []Entry
	for _, ip := range ips {
		info := endpoints.Classify(ip)
		if info != nil && info.Role != "" {
			out = append(out, Entry{
				TS:     0,
				Source: "endpoint",
				Text:   fmt.Sprintf("%s  %s (%s, %s)", ip, info.Label, info.Category, info.Scope),
				Ref: map[string]any{
					"address":  info.Address,
					"category": info.Category,
					"role":     info.Role,
					"scope":    info.Scope,
					"label":    info.Label,
				},
			})
		}
	}
	return out
}
