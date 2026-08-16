package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/siem"
)

func TestFlowSiemAPIRoutes(t *testing.T) {
	app, _, obs := setupIncidentTestApp(t)

	now := time.Now().Unix()

	// Seed syslog events
	msg1 := `date=2026-08-16 type="traffic" action="blocked" srcip=10.0.0.5 dstip=8.8.8.8 sentbyte=500 rcvdbyte=0 proto=17 srcport=54321 dstport=53`
	msg2 := `date=2026-08-16 type="traffic" action="accept" srcip=10.0.0.10 dstip=192.168.1.1 sentbyte=1200 rcvdbyte=2400 proto=6 srcport=44556 dstport=443`

	res1, _ := obs.DB.Exec(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message) VALUES (?, 'T1', '10.0.0.1', 4, 'blocked', ?)`, now-10, msg1)
	evID1, _ := res1.LastInsertId()
	_, _ = obs.DB.Exec(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message) VALUES (?, 'T1', '10.0.0.1', 6, 'accept', ?)`, now-5, msg2)

	// 1. GET /api/flow-siem/events
	req := withAdminAuth(httptest.NewRequest("GET", "/api/flow-siem/events?window=1h", nil))
	rec := httptest.NewRecorder()
	app.handleGetFlowSiemEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET flow-siem events got %d: %s", rec.Code, rec.Body.String())
	}

	var eventsResp struct {
		Total  int          `json:"total"`
		Events []siem.Event `json:"events"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &eventsResp)
	if eventsResp.Total != 2 || len(eventsResp.Events) != 2 {
		t.Fatalf("expected 2 events, got %+v", eventsResp)
	}

	// 2. GET /api/flow-siem/histogram
	req = withAdminAuth(httptest.NewRequest("GET", "/api/flow-siem/histogram?window=1h&buckets=10", nil))
	rec = httptest.NewRecorder()
	app.handleGetFlowSiemHistogram(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET flow-siem histogram got %d: %s", rec.Code, rec.Body.String())
	}

	var histResp struct {
		Buckets []siem.HistogramBucket `json:"buckets"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &histResp)
	if len(histResp.Buckets) != 10 {
		t.Fatalf("expected 10 buckets, got %d", len(histResp.Buckets))
	}

	// 3. GET /api/flow-siem/facets
	req = withAdminAuth(httptest.NewRequest("GET", "/api/flow-siem/facets?window=1h", nil))
	rec = httptest.NewRecorder()
	app.handleGetFlowSiemFacets(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET flow-siem facets got %d: %s", rec.Code, rec.Body.String())
	}

	var facetsResp siem.FacetsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &facetsResp)
	if facetsResp.EventsConsidered != 2 || len(facetsResp.TopSrcIPs) == 0 {
		t.Fatalf("expected facets populated, got %+v", facetsResp)
	}

	// 4. POST /api/flow-siem/alerts/suppress
	suppBody := `{"event_id": ` + strconv.FormatInt(evID1, 10) + `, "reason": "Expected DNS test"}`
	req = withOperatorAuth(httptest.NewRequest("POST", "/api/flow-siem/alerts/suppress", strings.NewReader(suppBody)))
	rec = httptest.NewRecorder()
	app.handleSuppressFlowSiemAlert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST suppress got %d: %s", rec.Code, rec.Body.String())
	}

	// After suppression, events list has 1 item
	req = withAdminAuth(httptest.NewRequest("GET", "/api/flow-siem/events?window=1h", nil))
	rec = httptest.NewRecorder()
	app.handleGetFlowSiemEvents(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &eventsResp)
	if eventsResp.Total != 1 {
		t.Fatalf("expected 1 event after suppression, got %d", eventsResp.Total)
	}

	// 5. POST /api/flow-siem/shun-ip and GET /api/flow-siem/shun-list
	shunBody := `{"ip": "198.51.100.99", "reason": "DDoS attacker"}`
	req = withOperatorAuth(httptest.NewRequest("POST", "/api/flow-siem/shun-ip", strings.NewReader(shunBody)))
	rec = httptest.NewRecorder()
	app.handleShunIP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST shun-ip got %d: %s", rec.Code, rec.Body.String())
	}

	req = withAdminAuth(httptest.NewRequest("GET", "/api/flow-siem/shun-list", nil))
	rec = httptest.NewRecorder()
	app.handleGetShunList(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "198.51.100.99") {
		t.Fatalf("GET shun-list got %d: %s", rec.Code, rec.Body.String())
	}
}

