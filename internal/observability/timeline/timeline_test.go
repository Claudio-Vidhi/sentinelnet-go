package timeline

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestBuildTimeline(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	schema := `
	CREATE TABLE incidents (
		id INTEGER PRIMARY KEY,
		tenant TEXT,
		opened_ts INTEGER,
		last_event_ts INTEGER
	);
	CREATE TABLE evidence (
		id INTEGER PRIMARY KEY,
		incident_id INTEGER,
		ts INTEGER,
		role TEXT,
		rule_id TEXT,
		rule_version TEXT,
		params_json TEXT,
		severity INTEGER,
		src_ip TEXT,
		dst_ip TEXT,
		switch_port TEXT,
		summary TEXT,
		attrs_json TEXT,
		event_id INTEGER,
		status TEXT,
		retracted_by_evidence_id INTEGER,
		retracted_by_rule_id TEXT,
		retracted_at INTEGER,
		retracted_reason TEXT
	);
	CREATE TABLE syslog_events (
		ts INTEGER,
		tenant TEXT,
		device_ip TEXT,
		severity INTEGER,
		action TEXT,
		message TEXT
	);
	CREATE TABLE flow_aggregates (
		window_start INTEGER,
		tenant TEXT,
		src_ip TEXT,
		dst_ip TEXT,
		total_bytes INTEGER,
		total_packets INTEGER
	);
	CREATE TABLE api_observations (
		ts INTEGER,
		tenant TEXT,
		device_ip TEXT,
		kind TEXT,
		summary_json TEXT
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	db.Exec(`INSERT INTO incidents (id, tenant, opened_ts, last_event_ts) VALUES (1, 'T1', 1000, 1500)`)
	db.Exec(`INSERT INTO evidence (id, incident_id, ts, role, rule_id, rule_version, summary, status, src_ip, dst_ip)
	         VALUES (10, 1, 1200, 'trigger', 'TEST_RULE', '1.0', 'Test evidence', 'active', '10.0.0.5', '8.8.8.8')`)
	db.Exec(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
	         VALUES (1100, 'T1', '10.0.0.5', 3, 'deny', 'Blocked packet')`)

	entries, err := Build(db, nil, 1)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(entries) < 2 {
		t.Errorf("expected at least 2 entries (evidence + syslog), got %d", len(entries))
	}
}
