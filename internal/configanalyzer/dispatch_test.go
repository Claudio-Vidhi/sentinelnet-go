package configanalyzer

import (
	"os"
	"path/filepath"
	"testing"
)

// writeBackup crea un file di backup per l'IP dentro dir e ne ritorna il path.
func writeBackup(t *testing.T, dir, ip, content string) {
	t.Helper()
	p := filepath.Join(dir, "backup-"+ip+".txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func resultMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("risultato non è una mappa: %T", v)
	}
	return m
}

// Un backup FortiGate deve essere analizzato come FortiOS: config_type
// corretto, flag firewall, envelope presente e niente vtp (che è solo IOS).
func TestAnalyzeDeviceDispatchesFortiOS(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.1", `#config-version=FGT-7.2
config system global
    set hostname "FGT-1"
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end`)

	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.1", "fortinet", "Sede A", ""))

	if res["config_type"] != "fortios" {
		t.Errorf("config_type = %v", res["config_type"])
	}
	if res["is_firewall"] != true {
		t.Errorf("is_firewall = %v", res["is_firewall"])
	}
	if res["firewall"] == nil {
		t.Error("envelope firewall assente per un FortiGate")
	}
	if _, hasVTP := res["vtp"]; hasVTP {
		t.Error("vtp presente su una config FortiOS (è solo IOS)")
	}
	if res["hostname"] != "FGT-1" {
		t.Errorf("hostname = %v, atteso quello della config", res["hostname"])
	}
	if res["tenant"] != "Sede A" {
		t.Errorf("tenant = %v, atteso il gruppo di inventario", res["tenant"])
	}
	// La validazione FortiOS deve esserci con la regola any->any rilevata.
	val, _ := res["validation"].(map[string]any)
	if val == nil {
		t.Fatal("validation assente")
	}
	if aa, _ := val["any_any_policies"].([]any); len(aa) != 1 {
		t.Errorf("any_any_policies = %v", val["any_any_policies"])
	}
}

// Un backup PAN-OS: config_type panos, envelope presente, struttura IOS
// tollerante, hostname dalla riga set, niente vtp.
func TestAnalyzeDeviceDispatchesPanos(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.2", `set deviceconfig system hostname PA-1
set address LAN ip-netmask 192.168.1.0/24
set rulebase security rules R1 action allow`)

	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.2", "palo_alto", "", ""))

	if res["config_type"] != "panos" {
		t.Errorf("config_type = %v", res["config_type"])
	}
	if res["is_firewall"] != true || res["firewall"] == nil {
		t.Errorf("firewall non valorizzato: is_firewall=%v firewall=%v", res["is_firewall"], res["firewall"])
	}
	if res["hostname"] != "PA-1" {
		t.Errorf("hostname = %v, atteso dalla riga set", res["hostname"])
	}
	if _, hasVTP := res["vtp"]; hasVTP {
		t.Error("vtp presente su una config PAN-OS")
	}
}

// Un backup IOS: config_type ios, NON firewall, firewall null, e vtp presente.
func TestAnalyzeDeviceDispatchesIOS(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.3", `hostname SW-1
!
vlan 10
 name USERS
!
vtp domain LAB
vtp mode transparent`)

	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.3", "cisco_ios", "", ""))

	if res["config_type"] != "ios" {
		t.Errorf("config_type = %v", res["config_type"])
	}
	if res["is_firewall"] != false {
		t.Errorf("is_firewall = %v, atteso false", res["is_firewall"])
	}
	if res["firewall"] != nil {
		t.Errorf("firewall = %v, atteso null per IOS", res["firewall"])
	}
	if _, hasVTP := res["vtp"]; !hasVTP {
		t.Error("vtp assente su una config IOS")
	}
	if res["hostname"] != "SW-1" {
		t.Errorf("hostname = %v", res["hostname"])
	}
}

// Il vendor ha la precedenza: un backup dal contenuto FortiOS ma con vendor
// cisco viene trattato come IOS (coerente con DetectConfigType).
func TestAnalyzeDeviceVendorWinsOverContent(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.4", "#config-version=FGT\nconfig system global\nend")

	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.4", "cisco", "", ""))
	if res["config_type"] != "ios" {
		t.Errorf("config_type = %v, atteso ios (vendor cisco vince sul contenuto)", res["config_type"])
	}
}

// Nessun backup per l'IP: nil, così l'handler risponde 404.
func TestAnalyzeDeviceNoBackup(t *testing.T) {
	if res := AnalyzeDevice(t.TempDir(), "10.9.9.9", "cisco_ios", "", ""); res != nil {
		t.Errorf("atteso nil senza backup, ottenuto %v", res)
	}
}

// L'hostname di inventario è un fallback quando la config non lo espone.
func TestAnalyzeDeviceInventoryHostnameFallback(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.5", "interface Gi0/1\n")
	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.5", "cisco_ios", "", "SW-DA-INVENTARIO"))
	if res["hostname"] != "SW-DA-INVENTARIO" {
		t.Errorf("hostname = %v, atteso il fallback di inventario", res["hostname"])
	}
}
