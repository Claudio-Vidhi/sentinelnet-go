package audit

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func loadFixture(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("testdata", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", name, err)
	}
	return string(b)
}

func TestFortiOSAuditScan_Clean(t *testing.T) {
	cleanCfg := loadFixture(t, "fortigate_clean.conf")
	res, err := RunNetSecAudit(cleanCfg, "FGT-CORE-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Vendor != VendorFortiOS {
		t.Errorf("vendor = %s; want %s", res.Vendor, VendorFortiOS)
	}
	if res.Score == nil || *res.Score < 85 {
		t.Errorf("expected high score for clean config, got %v", res.Score)
	}
	if res.Summary.Passed == 0 {
		t.Errorf("expected passed rules > 0")
	}

	// Verify all CIS FortiOS rules ran
	foundRules := make(map[string]bool)
	for _, r := range res.Rules {
		foundRules[r.ID] = true
	}
	if len(foundRules) != len(CISFortiOSRules) {
		t.Errorf("expected %d FortiOS rules evaluated, got %d", len(CISFortiOSRules), len(foundRules))
	}
}

func TestFortiOSAuditScan_Violations(t *testing.T) {
	badCfg := loadFixture(t, "fortigate_violations.conf")
	res, err := RunNetSecAudit(badCfg, "FGT-BAD-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Score == nil || *res.Score > 50 {
		t.Errorf("expected low score for violations config, got %v", res.Score)
	}
	if res.Summary.Failed == 0 {
		t.Errorf("expected failed rules > 0")
	}

	// Verify specific violations
	violations := map[string]string{
		"AUD-CIS-01": StatusFail, // insecure mgmt
		"AUD-CIS-02": StatusFail, // any-any policy
		"AUD-CIS-03": StatusFail, // weak TLS
		"AUD-CIS-04": StatusFail, // idle timeout
		"AUD-CIS-05": StatusFail, // snmp default community
	}
	for _, r := range res.Rules {
		if expectedStatus, ok := violations[r.ID]; ok {
			if r.Status != expectedStatus {
				t.Errorf("rule %s status = %s; want %s (detail: %s)", r.ID, r.Status, expectedStatus, r.Detail)
			}
			if len(r.Evidence) == 0 {
				t.Errorf("rule %s expected evidence for failure", r.ID)
			}
		}
	}
}

func TestFortiOSAuditScan_Partial(t *testing.T) {
	partCfg := loadFixture(t, "fortigate_partial.conf")
	res, err := RunNetSecAudit(partCfg, "FGT-PARTIAL-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Summary.Unknown == 0 {
		t.Errorf("expected unknown rules for partial config")
	}
	if res.Score == nil {
		t.Errorf("expected score calculated from assessed rules")
	}
}

func TestIOSAuditScan_Clean(t *testing.T) {
	cleanCfg := loadFixture(t, "ios_clean.conf")
	res, err := RunNetSecAudit(cleanCfg, "RTR-EDGE-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Vendor != VendorIOS {
		t.Errorf("vendor = %s; want %s", res.Vendor, VendorIOS)
	}
	if res.Score == nil || *res.Score < 85 {
		t.Errorf("expected high score for clean IOS config, got %v", res.Score)
	}
	if res.Summary.Passed == 0 {
		t.Errorf("expected passed rules > 0")
	}
}

func TestIOSAuditScan_Violations(t *testing.T) {
	badCfg := loadFixture(t, "ios_violations.conf")
	res, err := RunNetSecAudit(badCfg, "RTR-BAD-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Score == nil || *res.Score > 50 {
		t.Errorf("expected low score for IOS violations config, got %v", res.Score)
	}

	violations := map[string]string{
		"AUD-IOS-01": StatusFail, // AAA disabled
		"AUD-IOS-04": StatusFail, // VTY transport telnet
		"AUD-IOS-12": StatusFail, // enable password
		"AUD-IOS-15": StatusFail, // SNMP default community
		"AUD-IOS-19": StatusFail, // SSH version 1
	}
	for _, r := range res.Rules {
		if expectedStatus, ok := violations[r.ID]; ok {
			if r.Status != expectedStatus {
				t.Errorf("rule %s status = %s; want %s (detail: %s)", r.ID, r.Status, expectedStatus, r.Detail)
			}
		}
	}
}

func TestLinuxAuditScan_Clean(t *testing.T) {
	cleanCfg := loadFixture(t, "linux_clean.conf")
	res, err := RunNetSecAudit(cleanCfg, "SRV-LNX-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Vendor != VendorLinux {
		t.Errorf("vendor = %s; want %s", res.Vendor, VendorLinux)
	}
	if res.Score == nil || *res.Score < 85 {
		t.Errorf("expected high score for clean Linux config, got %v", res.Score)
	}
	if res.Summary.Passed == 0 {
		t.Errorf("expected passed rules > 0")
	}
}

func TestLinuxAuditScan_Violations(t *testing.T) {
	badCfg := loadFixture(t, "linux_violations.conf")
	res, err := RunNetSecAudit(badCfg, "SRV-BAD-01", "cis", "it")
	if err != nil {
		t.Fatalf("RunNetSecAudit failed: %v", err)
	}
	if res.Score == nil || *res.Score > 50 {
		t.Errorf("expected low score for Linux violations config, got %v", res.Score)
	}

	violations := map[string]string{
		"AUD-LNX-01": StatusFail, // PermitRootLogin yes
		"AUD-LNX-02": StatusFail, // PermitEmptyPasswords yes
		"AUD-LNX-06": StatusFail, // MaxAuthTries 10
		"AUD-LNX-11": StatusFail, // PASS_MAX_DAYS 99999
		"AUD-LNX-14": StatusFail, // ENCRYPT_METHOD MD5
		"AUD-LNX-17": StatusFail, // ip_forward = 1
	}
	for _, r := range res.Rules {
		if expectedStatus, ok := violations[r.ID]; ok {
			if r.Status != expectedStatus {
				t.Errorf("rule %s status = %s; want %s (detail: %s)", r.ID, r.Status, expectedStatus, r.Detail)
			}
		}
	}
}

func TestNISTAndPCIBenchmarks(t *testing.T) {
	cleanForti := loadFixture(t, "fortigate_clean.conf")
	resNIST, err := RunNetSecAudit(cleanForti, "FGT-01", "nist", "en")
	if err != nil {
		t.Fatalf("NIST scan failed: %v", err)
	}
	if resNIST.Benchmark != "nist" {
		t.Errorf("benchmark = %s; want nist", resNIST.Benchmark)
	}
	if len(resNIST.Rules) == 0 {
		t.Errorf("expected NIST rules evaluated")
	}

	resPCI, err := RunNetSecAudit(cleanForti, "FGT-01", "pci", "it")
	if err != nil {
		t.Fatalf("PCI scan failed: %v", err)
	}
	if resPCI.Benchmark != "pci" {
		t.Errorf("benchmark = %s; want pci", resPCI.Benchmark)
	}
	if len(resPCI.Rules) == 0 {
		t.Errorf("expected PCI rules evaluated")
	}
}

func TestMessagesAndGuidance(t *testing.T) {
	msgIT := RenderMessage("fos.mgmt_proto.insecure", "it", map[string]any{"count": 3})
	if msgIT == "" || !bytes.Contains([]byte(msgIT), []byte("3")) {
		t.Errorf("unexpected rendered message IT: %s", msgIT)
	}

	msgEN := RenderMessage("fos.mgmt_proto.insecure", "en", map[string]any{"count": 3})
	if msgEN == "" || !bytes.Contains([]byte(msgEN), []byte("3")) {
		t.Errorf("unexpected rendered message EN: %s", msgEN)
	}

	guid := GuidanceFor("check_management_protocols", "it")
	if guid["why"] == "" || guid["impact"] == "" {
		t.Errorf("expected non-empty guidance for check_management_protocols: %+v", guid)
	}
}

func TestDOCXExport(t *testing.T) {
	cleanCfg := loadFixture(t, "fortigate_clean.conf")
	scanRes, err := RunNetSecAudit(cleanCfg, "FGT-CORE-01", "cis", "it")
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	payload := map[string]any{
		"device_name":     scanRes.DeviceName,
		"benchmark_title": scanRes.BenchmarkTitle,
		"vendor":          scanRes.Vendor,
		"lang":            scanRes.Lang,
		"score":           scanRes.Score,
		"summary":         scanRes.Summary,
		"rules":           scanRes.Rules,
	}

	docxBytes, err := GenerateAuditDOCX(payload)
	if err != nil {
		t.Fatalf("GenerateAuditDOCX failed: %v", err)
	}
	if len(docxBytes) == 0 {
		t.Fatalf("expected non-empty docx bytes")
	}

	// Verify valid zip
	zr, err := zip.NewReader(bytes.NewReader(docxBytes), int64(len(docxBytes)))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}

	foundDocXML := false
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			foundDocXML = true
			break
		}
	}
	if !foundDocXML {
		t.Errorf("word/document.xml not found in docx archive")
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
