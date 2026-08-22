package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func testPolicyApp(t *testing.T) (*App, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })

	key := make([]byte, 32)
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{DataDir: dir}
	backupDir := cfg.BackupDir()
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatal(err)
	}

	return NewApp(cfg, st, nil, vault), st, backupDir
}

const sampleIOSConfig = `
hostname Core-R1
!
ip access-list extended WAN_IN
 10 permit tcp 10.0.0.0 0.0.255.255 host 192.168.1.100 eq 443
 20 permit tcp any any established
 30 deny ip any any
!
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 ip access-group WAN_IN in
!
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 10.0.0.254
`

const sampleFortiOSConfig = `
config system global
    set hostname "FGT-DC"
end
config router static
    edit 1
        set device "port1"
        set dst 10.0.0.0 255.0.0.0
    next
end
config firewall address
    edit "LAN_NET"
        set subnet 192.168.1.0 255.255.255.0
    next
    edit "WEB_SERVER"
        set subnet 10.0.0.50 255.255.255.255
    next
end
config firewall service custom
    edit "HTTPS_CUSTOM"
        set tcp-portrange 443
    next
end
config firewall policy
    edit 1
        set name "LAN_TO_WEB"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "LAN_NET"
        set dstaddr "WEB_SERVER"
        set action accept
        set schedule "always"
        set service "HTTPS_CUSTOM"
    next
end
`

func TestPolicyTraceIOS(t *testing.T) {
	app, st, backupDir := testPolicyApp(t)
	ip := "10.0.0.1"

	if err := st.UpsertDevice(&store.Device{IP: ip, Hostname: "Core-R1", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, ip+".txt"), []byte(sampleIOSConfig), 0644); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"src_ip":"10.0.1.5","dst_ip":"192.168.1.100","proto":"tcp","dport":443,"ingress_intf":"GigabitEthernet0/0"}`)
	req := httptest.NewRequest("POST", "/api/policy-test/"+ip+"/trace", bytes.NewReader(body))
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()

	app.handlePolicyTrace(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["verdict"] != "PERMIT" {
		t.Errorf("expected PERMIT, got %v", res["verdict"])
	}
}

func TestPolicyTraceFortiOS(t *testing.T) {
	app, st, backupDir := testPolicyApp(t)
	ip := "192.168.1.99"

	if err := st.UpsertDevice(&store.Device{IP: ip, Hostname: "FGT-DC", Vendor: "fortinet", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, ip+".txt"), []byte(sampleFortiOSConfig), 0644); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"src_ip":"192.168.1.50","dst_ip":"10.0.0.50","proto":"tcp","dport":443,"ingress_intf":"port2","egress_intf":"port1"}`)
	req := httptest.NewRequest("POST", "/api/policy-test/"+ip+"/trace", bytes.NewReader(body))
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()

	app.handlePolicyTrace(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["verdict"] != "PERMIT" {
		t.Errorf("expected PERMIT, got %v", res["verdict"])
	}
}

func TestPolicyExamples(t *testing.T) {
	app, st, backupDir := testPolicyApp(t)
	ip := "10.0.0.1"

	if err := st.UpsertDevice(&store.Device{IP: ip, Hostname: "Core-R1", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, ip+".txt"), []byte(sampleIOSConfig), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/policy-test/"+ip+"/examples", nil)
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()

	app.handlePolicyExamples(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var groups []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	if len(groups) == 0 {
		t.Errorf("expected example groups, got empty")
	}
}

func TestPolicyFindings(t *testing.T) {
	app, st, backupDir := testPolicyApp(t)
	ip := "10.0.0.1"

	if err := st.UpsertDevice(&store.Device{IP: ip, Hostname: "Core-R1", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, ip+".txt"), []byte(sampleIOSConfig), 0644); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/policy-test/"+ip+"/findings", nil)
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()

	app.handlePolicyFindings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyProve(t *testing.T) {
	app, st, backupDir := testPolicyApp(t)
	ip := "10.0.0.1"

	if err := st.UpsertDevice(&store.Device{IP: ip, Hostname: "Core-R1", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, ip+".txt"), []byte(sampleIOSConfig), 0644); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"witness":{"src_ip":"10.0.1.5","dst_ip":"192.168.1.100","proto":"tcp","dport":443,"ingress_intf":"GigabitEthernet0/0"},"expected_rule_id":"10"}`)
	req := httptest.NewRequest("POST", "/api/policy-test/"+ip+"/prove", bytes.NewReader(body))
	req = withIPParam(req, ip, adminClaims)
	rec := httptest.NewRecorder()

	app.handlePolicyProve(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if res["proven"] != true {
		t.Errorf("expected proven=true, got %v", res["proven"])
	}
}
