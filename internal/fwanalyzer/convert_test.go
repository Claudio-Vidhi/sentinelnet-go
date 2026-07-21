package fwanalyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Golden dall'output vero di convert_config del Python, nei due versi.
func TestConvertMatchesPythonGolden(t *testing.T) {
	for _, tc := range []struct{ src, from, to, golden string }{
		{"fortios_hq.conf", "fortios", "panos", "convert_f2p.json"},
		{"panos_hq.conf", "panos", "fortios", "convert_p2f.json"},
	} {
		t.Run(tc.from+"_to_"+tc.to, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.src))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ConvertConfig(string(raw), tc.from, tc.to)
			if err != nil {
				t.Fatal(err)
			}
			gotNorm := marshalNorm(t, got)

			wantRaw, err := os.ReadFile(filepath.Join("testdata", tc.golden))
			if err != nil {
				t.Fatal(err)
			}
			wantNorm := normalizeJSON(t, wantRaw)
			if gotNorm != wantNorm {
				t.Errorf("conversione diversa dal Python.\n--- Go ---\n%s\n\n--- Python ---\n%s", gotNorm, wantNorm)
			}
		})
	}
}

// Vendor non validi o coincidenti: errore, con i messaggi del Python (la UI li
// mostra come 400 detail).
func TestConvertConfigRejectsBadVendors(t *testing.T) {
	if _, err := ConvertConfig("x", "cisco", "panos"); err == nil {
		t.Error("vendor non firewall accettato")
	}
	if _, err := ConvertConfig("x", "fortios", "fortios"); err == nil {
		t.Error("vendor coincidenti accettati")
	}
	if _, err := ConvertConfig("x", "fortios", "panos"); err != nil {
		t.Errorf("conversione valida rifiutata: %v", err)
	}
}

// L'intestazione della preview usa il commento del vendor di destinazione
// (# per FortiOS, ! per PAN-OS) e riporta i conteggi.
func TestConvertPreviewHeader(t *testing.T) {
	res, err := ConvertConfig("config firewall address\n    edit \"A\"\n        set subnet 10.0.0.0 255.255.255.0\n    next\nend",
		"fortios", "panos")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.PreviewText, "! Anteprima conversione fortios -> panos") {
		t.Errorf("intestazione = %q", res.PreviewText[:60])
	}
	if len(res.Mapped) != 1 {
		t.Errorf("mapped = %d, atteso 1", len(res.Mapped))
	}
}

// prefixToMask e cidrSplit: casi limite.
func TestPrefixToMaskAndCidrSplit(t *testing.T) {
	if prefixToMask("24") != "255.255.255.0" {
		t.Errorf("/24 = %q", prefixToMask("24"))
	}
	if prefixToMask("0") != "0.0.0.0" {
		t.Errorf("/0 = %q", prefixToMask("0"))
	}
	if prefixToMask("33") != "" || prefixToMask("x") != "" {
		t.Error("prefisso non valido non rifiutato")
	}
	ip, mask := cidrSplit("10.1.2.0/24")
	if ip != "10.1.2.0" || mask != "255.255.255.0" {
		t.Errorf("cidrSplit = %q %q", ip, mask)
	}
	if ip, _ := cidrSplit("nientebarra"); ip != "" {
		t.Error("cidr senza barra accettato")
	}
}
