package audit

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestFortiOSAuditScan(t *testing.T) {
	fortiOSConfig := `
config system interface
    edit "port1"
        set allowaccess ping https ssh
    next
    edit "port2"
        set allowaccess ping telnet http
    next
end
config system global
    set admin-https-ssl-versions tlsv1-2 tlsv1-3
    set admintimeout 5
end
config system ntp
    set ntpsync enable
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`
	res, err := RunNetSecAudit(fortiOSConfig, "FGT-CORE-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Vendor != VendorFortiOS {
		t.Errorf("vendor = %s; want fortios", res.Vendor)
	}
	if res.Score == nil {
		t.Errorf("expected numeric score")
	}

	foundInsecureProtocols := false
	foundAnyAny := false
	for _, r := range res.Rules {
		if r.ID == "AUD-CIS-01" && r.Status == StatusFail {
			foundInsecureProtocols = true
		}
		if r.ID == "AUD-CIS-02" && r.Status == StatusFail {
			foundAnyAny = true
		}
	}
	if !foundInsecureProtocols {
		t.Errorf("expected AUD-CIS-01 to FAIL on port2 telnet/http")
	}
	if !foundAnyAny {
		t.Errorf("expected AUD-CIS-02 to FAIL on any-to-any policy")
	}
}

func TestIOSAuditScan(t *testing.T) {
	iosConfig := `
version 17.3
service timestamps debug datetime msec
service timestamps log datetime msec
aaa new-model
enable secret 9 $9$somehash
ip ssh version 2
line vty 0 4
 transport input ssh
 access-class 10 in
!
logging host 10.0.0.50
`
	res, err := RunNetSecAudit(iosConfig, "RTR-EDGE-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Vendor != VendorIOS {
		t.Errorf("vendor = %s; want ios", res.Vendor)
	}
	if res.Score == nil || *res.Score < 80 {
		t.Errorf("expected high score for well-hardened config, got %v", res.Score)
	}
}

func TestChecklistLifecycle(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	schema := `
	CREATE TABLE audit_templates (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		version INTEGER,
		name TEXT,
		status TEXT,
		created_ts INTEGER,
		created_by TEXT,
		notes TEXT
	);
	CREATE TABLE audit_template_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id INTEGER,
		ref TEXT,
		section_no INTEGER,
		section_title TEXT,
		title TEXT,
		guidance_why TEXT,
		guidance_good TEXT,
		guidance_how TEXT,
		thresholds_json TEXT,
		check_kind TEXT DEFAULT 'manual',
		severity_default TEXT DEFAULT 'media',
		is_prerequisite INTEGER DEFAULT 0,
		requires_evidence INTEGER DEFAULT 0,
		sort_order INTEGER DEFAULT 0
	);
	CREATE TABLE audit_engagements (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		template_id INTEGER,
		customer_name TEXT,
		tenant TEXT,
		site_id TEXT,
		created_ts INTEGER,
		status TEXT,
		assigned_to TEXT,
		scope_notes TEXT,
		onsite_or_remote TEXT,
		interviewee TEXT
	);
	CREATE TABLE audit_engagement_items (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		engagement_id INTEGER,
		item_ref TEXT,
		status TEXT DEFAULT 'non_valutato',
		severity TEXT,
		finding_text TEXT,
		recommendation_text TEXT,
		ai_assisted INTEGER DEFAULT 0
	);
	CREATE TABLE audit_evidence (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		engagement_id INTEGER,
		item_ref TEXT,
		kind TEXT,
		filename TEXT,
		path TEXT,
		payload_json TEXT,
		confidential INTEGER DEFAULT 1,
		created_ts INTEGER
	);
	CREATE TABLE audit_engagement_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		engagement_id INTEGER,
		item_ref TEXT,
		field_changed TEXT,
		old_value TEXT,
		new_value TEXT,
		changed_by TEXT,
		changed_ts INTEGER
	);
	`
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("schema: %v", err)
	}

	tplID, err := SeedDefaultTemplate(db)
	if err != nil {
		t.Fatalf("SeedDefaultTemplate failed: %v", err)
	}

	eng, err := CreateEngagement(db, "Acme Corp", "default", "HQ", "auditor1", "Full audit", "remote", "IT Manager", tplID)
	if err != nil {
		t.Fatalf("CreateEngagement failed: %v", err)
	}
	if len(eng.Items) == 0 {
		t.Fatalf("expected engagement items created from template")
	}

	err = UpdateItemAssessment(db, eng.ID, "1.3", "conforme", "bassa", "Schema di rete ricevuto e completo", "Nessuna", "auditor1", false)
	if err != nil {
		t.Fatalf("UpdateItemAssessment failed: %v", err)
	}

	html, err := GenerateAuditReportHTML(db, eng.ID)
	if err != nil {
		t.Fatalf("GenerateAuditReportHTML failed: %v", err)
	}
	if len(html) == 0 {
		t.Errorf("expected HTML report output")
	}
}
