package fwanalyzer

import (
	"os"
	"path/filepath"
	"testing"
)

// Golden dall'output vero di fw_analyzers.panos.analyze su testdata/panos_hq.conf.
func TestAnalyzePanosMatchesPythonGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "panos_hq.conf"))
	if err != nil {
		t.Fatal(err)
	}
	got := AnalyzePanos(string(raw))

	gotNorm := marshalNorm(t, got)
	wantRaw, err := os.ReadFile(filepath.Join("testdata", "panos_hq.envelope.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantNorm := normalizeJSON(t, wantRaw)
	if gotNorm != wantNorm {
		t.Errorf("envelope diverso dal Python.\n--- Go ---\n%s\n\n--- Python ---\n%s", gotNorm, wantNorm)
	}
}

func TestAnalyzePanosToleratesGarbage(t *testing.T) {
	for _, in := range []string{"", "random text", "set", "set address"} {
		env := AnalyzePanos(in)
		if env.Vendor != "panos" || env.Sections == nil {
			t.Errorf("envelope inatteso per %q: %+v", in, env)
		}
	}
}

// Le liste PAN-OS "[ a b c ]" vanno appiattite; un valore singolo resta tale.
func TestPanosValuesHandlesBracketLists(t *testing.T) {
	e := panosCollect(panosLines(
		`set address-group G static [ A B C ]`), "address-group")[0]
	got := e.values("static")
	if len(got) != 3 || got[0] != "A" || got[2] != "C" {
		t.Errorf("values = %#v", got)
	}

	single := panosCollect(panosLines(`set zone z network layer3 eth1`), "zone")[0]
	if v := single.values("network", "layer3"); len(v) != 1 || v[0] != "eth1" {
		t.Errorf("valore singolo = %#v", v)
	}
}

// L'ordine di prima apparizione degli oggetti è conservato: il frontend rende
// le righe in quell'ordine.
func TestPanosCollectPreservesOrder(t *testing.T) {
	lines := panosLines("set address Z ip-netmask 1.1.1.1/32\nset address A ip-netmask 2.2.2.2/32")
	got := panosCollect(lines, "address")
	if len(got) != 2 || got[0].name != "Z" || got[1].name != "A" {
		t.Errorf("ordine non conservato: %v", []string{got[0].name, got[1].name})
	}
}
