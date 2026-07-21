package configanalyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// normalizeWLC decodifica e ri-serializza a chiavi ordinate: il confronto col
// golden (generato con sort_keys=True) non dipende dall'ordine di marshalling,
// solo dall'ordine degli array (che è un contratto).
func normalizeWLC(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("JSON non valido: %v", err)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func marshalNormWLC(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return normalizeWLC(t, b)
}

// Golden dall'output vero di analyze_wlc_config del Python, per entrambe le
// piattaforme: AireOS ('config ...') e IOS-XE/Catalyst 9800 ('wlan <p> <id>').
func TestAnalyzeWLCConfigMatchesPythonGolden(t *testing.T) {
	for _, tc := range []struct{ conf, golden string }{
		{"wlc_aireos.txt", "wlc_aireos.json"},
		{"wlc_iosxe.txt", "wlc_iosxe.json"},
	} {
		t.Run(tc.conf, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.conf))
			if err != nil {
				t.Fatal(err)
			}
			got := marshalNormWLC(t, AnalyzeWLCConfig(string(raw)))

			wantRaw, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			want := normalizeWLC(t, wantRaw)
			if got != want {
				t.Errorf("analisi diversa dal Python.\n--- Go ---\n%s\n\n--- Python ---\n%s", got, want)
			}
		})
	}
}

// La piattaforma è derivata dal contenuto: righe 'config ...' = AireOS, blocchi
// 'wlan <profile> <id> <ssid>' = IOS-XE (9800). Il 9800 allega ios_base.
func TestAnalyzeWLCPlatformDetection(t *testing.T) {
	aireos := AnalyzeWLCConfig("config sysname X\nconfig wlan create 1 A B\n")
	if aireos.Platform != "aireos" {
		t.Errorf("platform = %q, atteso aireos", aireos.Platform)
	}
	if aireos.IOSBase != nil {
		t.Error("ios_base presente per AireOS")
	}

	iosxe := AnalyzeWLCConfig("hostname C9800\nwlan P 1 S\n no shutdown\n")
	if iosxe.Platform != "iosxe" {
		t.Errorf("platform = %q, atteso iosxe", iosxe.Platform)
	}
	if iosxe.IOSBase == nil {
		t.Error("ios_base assente per IOS-XE (9800)")
	}
}

// Un C9800 WPA3 (SAE) è riconosciuto come tale; 'shutdown' disabilita la WLAN.
func TestAnalyzeWLCiosxeSecurity(t *testing.T) {
	res := AnalyzeWLCConfig("wlan Sec 1 S\n security wpa wpa3\n sae\n no shutdown\nwlan Off 2 O\n shutdown\n")
	if len(res.Wlans) != 2 {
		t.Fatalf("wlan = %d, attese 2", len(res.Wlans))
	}
	if res.Wlans[0].Security != "WPA3" {
		t.Errorf("wlan 1 security = %q, atteso WPA3", res.Wlans[0].Security)
	}
	if res.Wlans[1].Enabled {
		t.Error("wlan 2 (shutdown) risulta abilitata")
	}
	if len(res.Validation.DisabledWlans) != 1 {
		t.Errorf("disabled_wlans = %v", res.Validation.DisabledWlans)
	}
}

// Liste vuote su input vuoto: mai null (il frontend le itera). Piattaforma
// iosxe di default (nessuna riga 'config ...').
func TestAnalyzeWLCEmptyListsNotNull(t *testing.T) {
	norm := marshalNormWLC(t, AnalyzeWLCConfig(""))
	for _, key := range []string{`"wlans"`, `"dynamic_interfaces"`, `"radius_servers"`} {
		if !strings.Contains(norm, key+": []") {
			t.Errorf("%s non è [] su input vuoto:\n%s", key, norm)
		}
	}
	if strings.Contains(norm, "null") {
		t.Errorf("output contiene null:\n%s", norm)
	}
}

// AnalyzeDevice instrada un backup WLC (vendor cisco_wlc) all'analizzatore WLC:
// config_type wlc-aireos, non firewall, niente vtp (solo IOS).
func TestAnalyzeDeviceDispatchesWLC(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.9", "config sysname WLC-1\nconfig wlan create 5 Corp Corp\nconfig wlan enable 5\n")

	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.9", "cisco_wlc", "Sede A", ""))

	if res["config_type"] != "wlc-aireos" {
		t.Errorf("config_type = %v", res["config_type"])
	}
	if res["is_firewall"] != false {
		t.Errorf("is_firewall = %v, atteso false", res["is_firewall"])
	}
	if res["firewall"] != nil {
		t.Errorf("firewall = %v, atteso null", res["firewall"])
	}
	if _, hasVTP := res["vtp"]; hasVTP {
		t.Error("vtp presente su una config WLC")
	}
	if res["hostname"] != "WLC-1" {
		t.Errorf("hostname = %v", res["hostname"])
	}
	if res["platform"] != "aireos" {
		t.Errorf("platform = %v", res["platform"])
	}
}

// DIVERGENZA §11: un Catalyst 9800 (vendor cisco_9800, contenuto IOS-XE) viene
// instradato all'analizzatore WLC — mostra la tabella WLAN e conserva l'analisi
// IOS completa sotto ios_base. Nel Python cisco_9800 sarebbe 'ios'.
func TestAnalyzeDeviceDispatchesC9800(t *testing.T) {
	dir := t.TempDir()
	writeBackup(t, dir, "10.0.0.10", "hostname C9800-EDGE\nwlan Corp 1 Corp-SSID\n security wpa wpa2\n no shutdown\ninterface Vlan10\n ip address 10.0.10.1 255.255.255.0\n")

	res := resultMap(t, AnalyzeDevice(dir, "10.0.0.10", "cisco_9800", "Sede A", ""))

	if res["config_type"] != "wlc-aireos" {
		t.Errorf("config_type = %v, atteso wlc-aireos (routing cisco_9800)", res["config_type"])
	}
	if res["platform"] != "iosxe" {
		t.Errorf("platform = %v, atteso iosxe", res["platform"])
	}
	wlans, _ := res["wlans"].([]any)
	if len(wlans) != 1 {
		t.Fatalf("wlans = %v, attesa 1 (la tabella WLAN del 9800)", res["wlans"])
	}
	if res["ios_base"] == nil {
		t.Error("ios_base assente: l'analisi IOS completa deve essere conservata")
	}
	if res["hostname"] != "C9800-EDGE" {
		t.Errorf("hostname = %v", res["hostname"])
	}
}
