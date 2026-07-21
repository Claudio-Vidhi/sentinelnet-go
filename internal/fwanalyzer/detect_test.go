package fwanalyzer

import "testing"

// I casi attesi sono verificati contro detect_config_type del Python, con
// l'unica eccezione dichiarata di cisco_9800 (vedi DIVERGENZE §11).
func TestDetectConfigType(t *testing.T) {
	cases := []struct {
		content, vendor, want string
	}{
		// Sniffing dal contenuto (vendor vuoto).
		{"#config-version=FGT\nconfig system global\nend", "", TypeFortiOS},
		{"config system interface\nedit x\nend", "", TypeFortiOS},
		{"set deviceconfig system hostname PA", "", TypePanOS},
		{"set mgt-config users admin", "", TypePanOS},
		{"config wlan\n", "", TypeWLCAireOS},
		{"System Name..... WLC1", "", TypeWLCAireOS},
		{"hostname SW1\ninterface Gi0/1", "", TypeIOS},
		{"", "", TypeIOS},
		// Il vendor decide e ha la precedenza sul contenuto.
		{"anything", "fortinet", TypeFortiOS},
		{"anything", "palo_alto", TypePanOS},
		{"anything", "cisco_wlc", TypeWLCAireOS},
		// DIVERGENZA §11: il Python instrada cisco_9800 -> ios; noi lo mandiamo
		// all'analizzatore WLC così il Catalyst 9800 mostra la tabella WLAN.
		{"anything", "cisco_9800", TypeWLCAireOS},
		// Vendor noto non-firewall forza ios anche su contenuto FortiOS.
		{"#config-version=FGT", "cisco", TypeIOS},
	}
	for _, c := range cases {
		if got := DetectConfigType(c.content, c.vendor); got != c.want {
			t.Errorf("DetectConfigType(%q, %q) = %q, atteso %q",
				c.content[:min(len(c.content), 30)], c.vendor, got, c.want)
		}
	}
}
