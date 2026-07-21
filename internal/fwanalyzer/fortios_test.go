package fwanalyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Il golden è l'output vero di fw_analyzers.fortios.analyze del Python su
// testdata/fortios_hq.conf. L'envelope è un contratto verso il frontend
// (id sezione, label_key, colonne, ordine righe): va riprodotto fedelmente.
func TestAnalyzeFortiOSMatchesPythonGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "fortios_hq.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := AnalyzeFortiOS(string(raw))
	gotNorm := marshalNorm(t, got)

	wantRaw, err := os.ReadFile(filepath.Join("testdata", "fortios_hq.envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantNorm := normalizeJSON(t, wantRaw)

	if gotNorm != wantNorm {
		t.Errorf("envelope diverso dal Python.\n--- Go ---\n%s\n\n--- Python ---\n%s", gotNorm, wantNorm)
	}
}

// normalizeJSON decodifica e ri-serializza con chiavi ordinate, così il
// confronto non dipende dall'ordine di marshalling. Go ordina le chiavi delle
// mappe in MarshalIndent, che è ciò che rende il confronto stabile contro il
// golden Python generato con sort_keys=True.
func normalizeJSON(t *testing.T, b []byte) string {
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

// marshalNorm serializza un valore e lo normalizza a chiavi ordinate.
func marshalNorm(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return normalizeJSON(t, b)
}

// L'analizzatore non deve mai sollevare: input vuoto o spazzatura danno un
// envelope valido con sezioni vuote (non nil), così il frontend rende tabelle
// vuote invece di rompersi.
func TestAnalyzeFortiOSToleratesGarbage(t *testing.T) {
	for _, in := range []string{"", "spazzatura\nnon config", "config\nedit\nset"} {
		env := AnalyzeFortiOS(in)
		if env.Vendor != "fortios" {
			t.Errorf("vendor = %q", env.Vendor)
		}
		if env.Sections == nil {
			t.Error("sections nil invece di lista vuota")
		}
		for _, s := range env.Sections {
			if s.Rows == nil {
				t.Errorf("sezione %q ha rows nil", s.ID)
			}
		}
	}
}

// I segreti nelle impostazioni VPN SSL sono mascherati: un backup con la
// psksecret in chiaro non deve esporla nell'envelope.
func TestAnalyzeFortiOSMasksSSLSecrets(t *testing.T) {
	cfg := `config vpn ssl settings
    set servercert "Fortinet_SSL"
    set psksecret "SuperSegreto123"
end`
	env := AnalyzeFortiOS(cfg)
	var ssl *Section
	for i := range env.Sections {
		if env.Sections[i].ID == "vpn_ssl" {
			ssl = &env.Sections[i]
		}
	}
	if ssl == nil {
		t.Fatal("sezione vpn_ssl assente")
	}
	for _, row := range ssl.Rows {
		if row["key"] == "psksecret" && row["value"] != "***REDACTED***" {
			t.Errorf("psksecret non mascherata: %q", row["value"])
		}
		if row["value"] == "SuperSegreto123" {
			t.Error("segreto in chiaro nell'envelope")
		}
	}
}

// Le stringhe tra apici con spazi restano un token unico.
func TestFortiTokensRespectsQuotes(t *testing.T) {
	toks := fortiTokens(`set comment "rete interna sede A"`)
	if len(toks) != 3 || toks[2] != "rete interna sede A" {
		t.Errorf("token = %#v", toks)
	}
}
