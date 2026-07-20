package arp

import "testing"

func TestParseOutputVendorFormats(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		want  Entry
		count int
	}{
		{
			name:  "cisco ios",
			in:    "Internet  10.0.0.1    5   aabb.ccdd.eeff  ARPA   Vlan10",
			want:  Entry{MAC: "aabb.ccdd.eeff", IP: "10.0.0.1", VLAN: "10", Interface: "Vlan10"},
			count: 1,
		},
		{
			name:  "fortios",
			in:    "10.10.5.23     00:0c:29:3a:bb:1f     internal1",
			want:  Entry{MAC: "00:0c:29:3a:bb:1f", IP: "10.10.5.23", VLAN: "", Interface: "internal1"},
			count: 1,
		},
		{
			name:  "juniper no-resolve",
			in:    "00:1b:c0:aa:bb:cc 192.168.1.44    192.168.1.44     ge-0/0/1.0",
			want:  Entry{MAC: "00:1b:c0:aa:bb:cc", IP: "192.168.1.44", VLAN: "", Interface: "ge-0/0/1.0"},
			count: 1,
		},
		{
			// Ultimo token numerico (la VLAN in colonna) → nessuna interfaccia.
			name:  "ultimo token numerico",
			in:    "10.1.1.9        00-1a-4b-2c-3d-4e   dynamic   5",
			want:  Entry{MAC: "00-1a-4b-2c-3d-4e", IP: "10.1.1.9", VLAN: "", Interface: ""},
			count: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseOutput(c.in)
			if len(got) != c.count {
				t.Fatalf("entry = %d, attese %d (%+v)", len(got), c.count, got)
			}
			if got[0] != c.want {
				t.Errorf("got %+v, want %+v", got[0], c.want)
			}
		})
	}
}

// Righe senza MAC o senza IP (intestazioni, totali) vanno ignorate.
func TestParseOutputSkipsNonBindingLines(t *testing.T) {
	in := "Protocol  Address     Age (min)  Hardware Addr   Type   Interface\n" +
		"Total entries: 3\n" +
		"Internet  10.0.0.1    5   aabb.ccdd.eeff  ARPA   Vlan10\n"
	if got := ParseOutput(in); len(got) != 1 {
		t.Fatalf("entry = %d, attesa 1 (%+v)", len(got), got)
	}
}

// Il broadcast in forma puntata viene scartato (come nel Python).
func TestParseOutputDiscardsDottedBroadcast(t *testing.T) {
	in := "Internet  10.0.0.255  -   ffff.ffff.ffff  ARPA   Vlan10\n" +
		"Internet  10.0.0.9    -   0000.0000.0000  ARPA   Vlan10\n"
	if got := ParseOutput(in); len(got) != 0 {
		t.Fatalf("entry = %d, attese 0 (%+v)", len(got), got)
	}
}

// L'interfaccia non deve coincidere con il MAC o con l'IP della riga.
func TestParseOutputInterfaceNotMacOrIP(t *testing.T) {
	got := ParseOutput("10.0.0.5 aa:bb:cc:dd:ee:ff")
	if len(got) != 1 {
		t.Fatalf("entry = %d, attesa 1", len(got))
	}
	if got[0].Interface != "" {
		t.Errorf("interfaccia = %q, attesa vuota", got[0].Interface)
	}
}

// Limite noto ereditato dal Python: la regex MAC copre solo le forme a sei
// gruppi da due cifre (":" o "-") e quella puntata a tre gruppi da quattro.
// I formati HP/ProCurve "001a4b-2c3d4e" e "001a-4b2c-3d4e" NON sono
// riconosciuti — né qui né in collectors/arp_collector.py. Il test lo fissa
// come comportamento atteso: se un giorno si decide di estendere la regex,
// va fatto in entrambe le implementazioni insieme.
func TestParseOutputHPFormatsUnsupported(t *testing.T) {
	for _, line := range []string{
		"10.1.1.9  001a4b-2c3d4e  dynamic",
		"10.1.1.9  001a-4b2c-3d4e  dynamic",
	} {
		if got := ParseOutput(line); len(got) != 0 {
			t.Errorf("%q: entry = %d, attese 0 (limite noto) — %+v", line, len(got), got)
		}
	}
}

func TestParseOutputEmpty(t *testing.T) {
	if got := ParseOutput(""); len(got) != 0 {
		t.Fatalf("entry = %d, attese 0", len(got))
	}
}
