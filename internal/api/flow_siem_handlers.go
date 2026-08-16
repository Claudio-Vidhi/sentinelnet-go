package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/siem"
)

const maxScanSyslog = 20000

// GET /api/flow-siem/events
func (a *App) handleGetFlowSiemEvents(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"total": 0, "limit": 100, "offset": 0, "events": []any{}})
		return
	}

	q := r.URL.Query().Get("q")
	window := r.URL.Query().Get("window")
	action := r.URL.Query().Get("action")
	tenant := r.URL.Query().Get("tenant")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	cutoff := time.Now().Unix() - int64(siem.WindowToSeconds(window))

	var wantDeny *bool
	if action != "" {
		d := strings.ToUpper(strings.TrimSpace(action)) == "DENY"
		wantDeny = &d
	}

	filterField, filterVal := siem.ParseFieldQuery(q)
	needle := ""
	if filterField == "" && q != "" {
		needle = strings.ToLower(q)
	}

	query := `SELECT s.id, s.ts, s.tenant, s.device_ip, s.severity, s.action, s.message
	          FROM syslog_events AS s
	          WHERE s.ts >= ?`
	var args []any
	args = append(args, cutoff)

	if tenant != "" && tenant != "all" {
		if allowedTenants != nil && !containsStr(allowedTenants, tenant) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", tenant))
			return
		}
		query += ` AND s.tenant = ?`
		args = append(args, tenant)
	} else if allowedTenants != nil {
		if len(allowedTenants) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"total": 0, "limit": limit, "offset": offset, "events": []any{}})
			return
		}
		query += fmt.Sprintf(` AND s.tenant IN (%s)`, sqlInPlaceholders(len(allowedTenants)))
		for _, t := range allowedTenants {
			args = append(args, t)
		}
	}

	query += ` AND NOT EXISTS (SELECT 1 FROM siem_suppressions x WHERE x.event_id = s.id)
	          ORDER BY s.ts DESC, s.id DESC LIMIT ? OFFSET ?`

	wanted := offset + limit
	batch := limit * 4
	if batch < 500 {
		batch = 500
	}
	if batch > 2000 {
		batch = 2000
	}

	var events []siem.Event
	scanned := 0

	for len(events) < wanted && scanned < maxScanSyslog {
		currentArgs := append([]any{}, args...)
		currentArgs = append(currentArgs, batch, scanned)

		rows, err := a.obs.DB.Query(query, currentArgs...)
		if err != nil {
			break
		}

		countInBatch := 0
		for rows.Next() {
			countInBatch++
			var id int64
			var ts int64
			var rowTenant, devIP, actionRaw, msg string
			var sev sql.NullInt64

			if err := rows.Scan(&id, &ts, &rowTenant, &devIP, &sev, &actionRaw, &msg); err != nil {
				continue
			}

			var sevPtr *int
			if sev.Valid {
				v := int(sev.Int64)
				sevPtr = &v
			}

			ev := siem.ToEvent(id, ts, rowTenant, devIP, sevPtr, actionRaw, msg)

			if tenant != "" && tenant != "all" && !strings.EqualFold(ev.Tenant, tenant) {
				continue
			}
			if wantDeny != nil && ev.IsDeny != *wantDeny {
				continue
			}
			if filterField != "" {
				var fVal string
				switch filterField {
				case "src_ip":
					fVal = ev.SrcIP
				case "dst_ip":
					fVal = ev.DstIP
				case "action":
					if ev.IsDeny {
						fVal = "deny"
					} else {
						fVal = strings.ToLower(ev.Action)
					}
				case "threat_flag":
					fVal = strings.ToLower(ev.ThreatFlag)
				case "proto":
					fVal = strings.ToLower(ev.Proto)
				case "device_ip":
					fVal = strings.ToLower(ev.DeviceIP)
				case "tenant":
					fVal = strings.ToLower(ev.Tenant)
				}
				if strings.ToLower(fVal) != filterVal {
					continue
				}
			} else if needle != "" {
				haystack := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s %s %s",
					ev.SrcIP, ev.DstIP, ev.Action, ev.Proto, ev.DeviceIP, ev.Tenant, ev.ThreatFlag, ev.Message))
				if !strings.Contains(haystack, needle) {
					continue
				}
			}

			events = append(events, ev)
		}
		rows.Close()

		scanned += countInBatch
		if countInBatch < batch {
			break
		}
	}

	paged := []siem.Event{}
	if offset < len(events) {
		end := offset + limit
		if end > len(events) {
			end = len(events)
		}
		paged = events[offset:end]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"total":  len(events),
		"limit":  limit,
		"offset": offset,
		"events": paged,
	})
}

// GET /api/flow-siem/histogram
func (a *App) handleGetFlowSiemHistogram(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, map[string]any{"window": "24h", "bucket_sec": 2880, "buckets": []any{}})
		return
	}

	window := r.URL.Query().Get("window")
	tenant := r.URL.Query().Get("tenant")
	buckets, _ := strconv.Atoi(r.URL.Query().Get("buckets"))
	if buckets < 10 || buckets > 100 {
		buckets = 30
	}

	windowSec := siem.WindowToSeconds(window)
	bucketSec := windowSec / buckets
	if bucketSec < 1 {
		bucketSec = 1
	}

	now := time.Now().Unix()
	start := now - int64(windowSec)

	query := `SELECT ((ts - ?) / ?) AS bucket_index,
	                 COUNT(*) AS n,
	                 SUM(CASE WHEN lower(coalesce(action,'')) IN ('deny','drop','blocked','block','reject','reset-both','reset-server','reset-client','server-rst','client-rst') THEN 1 ELSE 0 END) AS denies
	          FROM syslog_events
	          WHERE ts >= ?`
	var args []any
	args = append(args, start, bucketSec, start)

	if tenant != "" && tenant != "all" {
		if allowedTenants != nil && !containsStr(allowedTenants, tenant) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", tenant))
			return
		}
		query += ` AND tenant = ?`
		args = append(args, tenant)
	} else if allowedTenants != nil {
		if len(allowedTenants) == 0 {
			writeJSON(w, http.StatusOK, map[string]any{"window": window, "bucket_sec": bucketSec, "buckets": []any{}})
			return
		}
		query += fmt.Sprintf(` AND tenant IN (%s)`, sqlInPlaceholders(len(allowedTenants)))
		for _, t := range allowedTenants {
			args = append(args, t)
		}
	}

	query += ` GROUP BY bucket_index`

	rows, err := a.obs.DB.Query(query, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	counts := map[int][2]int{}
	for rows.Next() {
		var idx, n, denies int
		if err := rows.Scan(&idx, &n, &denies); err == nil {
			if idx >= 0 && idx < buckets {
				counts[idx] = [2]int{n, denies}
			}
		}
	}

	var result []siem.HistogramBucket
	for i := 0; i < buckets; i++ {
		c := counts[i]
		tBucket := time.Unix(start+int64(i*bucketSec), 0).Format("15:04")
		result = append(result, siem.HistogramBucket{
			BucketIndex: i,
			Timestamp:   tBucket,
			Count:       c[0],
			DenyCount:   c[1],
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"window":     window,
		"bucket_sec": bucketSec,
		"buckets":    result,
	})
}

// GET /api/flow-siem/facets
func (a *App) handleGetFlowSiemFacets(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeJSON(w, http.StatusOK, siem.FacetsResponse{
			TopSrcIPs:   []siem.FacetItem{},
			TopDstIPs:   []siem.FacetItem{},
			ThreatFlags: []siem.FacetItem{},
			Actions:     []siem.FacetItem{},
		})
		return
	}

	window := r.URL.Query().Get("window")
	tenant := r.URL.Query().Get("tenant")
	cutoff := time.Now().Unix() - int64(siem.WindowToSeconds(window))

	query := `SELECT s.id, s.ts, s.tenant, s.device_ip, s.severity, s.action, s.message
	          FROM syslog_events AS s
	          WHERE s.ts >= ?`
	var args []any
	args = append(args, cutoff)

	if tenant != "" && tenant != "all" {
		if allowedTenants != nil && !containsStr(allowedTenants, tenant) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito.", tenant))
			return
		}
		query += ` AND s.tenant = ?`
		args = append(args, tenant)
	} else if allowedTenants != nil {
		if len(allowedTenants) == 0 {
			writeJSON(w, http.StatusOK, siem.FacetsResponse{})
			return
		}
		query += fmt.Sprintf(` AND s.tenant IN (%s)`, sqlInPlaceholders(len(allowedTenants)))
		for _, t := range allowedTenants {
			args = append(args, t)
		}
	}

	query += ` AND NOT EXISTS (SELECT 1 FROM siem_suppressions x WHERE x.event_id = s.id)
	          ORDER BY s.ts DESC LIMIT 2000`

	rows, err := a.obs.DB.Query(query, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	srcCounts := map[string]int{}
	dstCounts := map[string]int{}
	threatCounts := map[string]int{}
	actionCounts := map[string]int{}
	totalConsidered := 0

	for rows.Next() {
		totalConsidered++
		var id, ts int64
		var rowTenant, devIP, actionRaw, msg string
		var sev sql.NullInt64
		if err := rows.Scan(&id, &ts, &rowTenant, &devIP, &sev, &actionRaw, &msg); err != nil {
			continue
		}
		var sevPtr *int
		if sev.Valid {
			v := int(sev.Int64)
			sevPtr = &v
		}
		ev := siem.ToEvent(id, ts, rowTenant, devIP, sevPtr, actionRaw, msg)

		if ev.SrcIP != "" {
			srcCounts[ev.SrcIP]++
		}
		if ev.DstIP != "" {
			dstCounts[ev.DstIP]++
		}
		if ev.ThreatFlag != "" {
			threatCounts[ev.ThreatFlag]++
		}
		actLabel := "DENY"
		if !ev.IsDeny {
			if ev.Action != "" {
				actLabel = ev.Action
			} else {
				actLabel = "N/D"
			}
		}
		actionCounts[actLabel]++
	}

	topN := func(m map[string]int, n int) []siem.FacetItem {
		var list []siem.FacetItem
		for k, v := range m {
			list = append(list, siem.FacetItem{Value: k, Count: v})
		}
		sort.Slice(list, func(i, j int) bool {
			return list[i].Count > list[j].Count
		})
		if len(list) > n {
			list = list[:n]
		}
		return list
	}

	writeJSON(w, http.StatusOK, siem.FacetsResponse{
		TopSrcIPs:        topN(srcCounts, 5),
		TopDstIPs:        topN(dstCounts, 5),
		ThreatFlags:      topN(threatCounts, 5),
		Actions:          topN(actionCounts, 6),
		EventsConsidered: totalConsidered,
	})
}

type alertSuppressReq struct {
	EventID int64  `json:"event_id"`
	Reason  string `json:"reason"`
}

// POST /api/flow-siem/alerts/suppress
func (a *App) handleSuppressFlowSiemAlert(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.obs == nil {
		writeErr(w, http.StatusInternalServerError, "Database osservabilita non disponibile.")
		return
	}

	var req alertSuppressReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	var rowTenant string
	err := a.obs.DB.QueryRow(`SELECT tenant FROM syslog_events WHERE id = ?`, req.EventID).Scan(&rowTenant)
	if err != nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("Evento %d non trovato.", req.EventID))
		return
	}
	if allowedTenants != nil && !containsStr(allowedTenants, rowTenant) {
		writeErr(w, http.StatusForbidden, "Evento non consentito per il tuo profilo.")
		return
	}

	now := time.Now().Unix()
	reason := req.Reason
	if reason == "" {
		reason = "Confermato falso positivo"
	}

	_, err = a.obs.DB.Exec(
		`INSERT OR REPLACE INTO siem_suppressions (event_id, ts, tenant, reason, suppressed_by)
		 VALUES (?, ?, ?, ?, ?)`,
		req.EventID, now, rowTenant, reason, claims.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog(fmt.Sprintf("Allerta Flow SIEM (evento #%d) soppressa da '%s': %s", req.EventID, claims.Username, reason))
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "event_id": req.EventID, "suppressed": true})
}

type shunIPReq struct {
	IP     string `json:"ip"`
	Reason string `json:"reason"`
}

// POST /api/flow-siem/shun-ip
func (a *App) handleShunIP(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())

	var req shunIPReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	reason := req.Reason
	if reason == "" {
		reason = "Traffic anomaly or threat shun requested"
	}

	entry := siem.AddShun(req.IP, reason, claims.Username)
	a.auditLog(fmt.Sprintf("IP '%s' aggiunto alla lista shun da '%s': %s", req.IP, claims.Username, reason))

	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "success",
		"ip":       req.IP,
		"shunned":  true,
		"details":  entry,
	})
}

// GET /api/flow-siem/shun-list
func (a *App) handleGetShunList(w http.ResponseWriter, r *http.Request) {
	shuns := siem.ListShuns()
	writeJSON(w, http.StatusOK, map[string]any{"shunned_ips": shuns})
}
