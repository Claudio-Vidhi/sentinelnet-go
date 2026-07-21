package fwanalyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden dall'output vero di analyze_fortios_config del Python.
func TestAnalyzeFortiOSStructuredMatchesPythonGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "fortios_hq.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := AnalyzeFortiOSStructured(string(raw))

	gotNorm := marshalNorm(t, got)
	wantRaw, err := os.ReadFile(filepath.Join("testdata", "fortios_hq.structured.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantNorm := normalizeJSON(t, wantRaw)
	if gotNorm != wantNorm {
		t.Errorf("analisi diversa dal Python.\n--- Go ---\n%s\n\n--- Python ---\n%s", gotNorm, wantNorm)
	}
}

// Le liste vuote devono restare [] (non null): il Python le emette così e il
// frontend le itera. Su una config minima ogni sezione vuota è una lista.
func TestAnalyzeFortiOSStructuredEmptyListsNotNull(t *testing.T) {
	got := AnalyzeFortiOSStructured("config system global\n    set hostname X\nend")
	norm := marshalNorm(t, got)
	if strings.Contains(norm, "null") {
		t.Errorf("output contiene null: una lista vuota è diventata null\n%s", norm)
	}
}

// La validazione riconosce le regole any->any accettate, quelle disabilitate e
// le interfacce con management insicuro.
func TestFortiOSValidationFlags(t *testing.T) {
	cfg := `config system interface
    edit "wan"
        set allowaccess ping https telnet
    next
end
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
    edit 2
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status disable
    next
end`
	v := AnalyzeFortiOSStructured(cfg).Validation
	if len(v.AnyAnyPolicies) != 2 {
		t.Errorf("any_any = %v, attese 2", v.AnyAnyPolicies)
	}
	if len(v.DisabledPolicies) != 1 {
		t.Errorf("disabled = %v, attesa 1", v.DisabledPolicies)
	}
	if len(v.InsecureMgmtInterfaces) != 1 || v.InsecureMgmtInterfaces[0].Name != "wan" {
		t.Errorf("insecure_mgmt = %+v", v.InsecureMgmtInterfaces)
	}
	if !v.LoggingDisabled {
		t.Error("logging_disabled falso senza sezione di logging")
	}
}
