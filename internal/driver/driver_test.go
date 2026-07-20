package driver

import "testing"

// fakeRunner restituisce un output fisso per il comando atteso, e stringa vuota
// per qualunque altro: verifica anche che il driver invii il comando giusto.
type fakeRunner struct {
	expect string
	out    string
	got    string
}

func (f *fakeRunner) Run(cmd string) string {
	f.got = cmd
	if cmd == f.expect {
		return f.out
	}
	return ""
}

func TestGetVersionPerVendor(t *testing.T) {
	cases := []struct {
		name    string
		drv     Driver
		cmd     string
		out     string
		want    string
		backup  string
		arpComm string
	}{
		{
			name:    "cisco_ios",
			drv:     CiscoIOS{},
			cmd:     "show version",
			out:     "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)",
			want:    "15.2(7)E3",
			backup:  "show running-config",
			arpComm: "show ip arp",
		},
		{
			name:    "cisco_cbs",
			drv:     CiscoCBS{},
			cmd:     "show version",
			out:     "Active-image: flash://system/images/image_cbs_1.img\n  Version: 3.2.0.84\n",
			want:    "3.2.0.84",
			backup:  "show running-config",
			arpComm: "show arp",
		},
		{
			name:    "cisco_wlc",
			drv:     CiscoWLC{},
			cmd:     "show sysinfo",
			out:     "Product Version.................................. 8.10.190.0\nRTOS Version..... 8.10.190.0",
			want:    "8.10.190.0",
			backup:  "show run-config commands",
			arpComm: "show arp switch",
		},
		{
			name:    "aruba_os",
			drv:     ArubaOS{},
			cmd:     "show version",
			out:     "ArubaOS (MODEL: 7010), Version 8.6.0.4",
			want:    "8.6.0.4",
			backup:  "show running-config",
			arpComm: "show arp",
		},
		{
			name:    "hp_procurve",
			drv:     HPProcurve{},
			cmd:     "show system",
			out:     " Status and Counters - General System Information\n\n  Firmware revision : WB.16.10.0012\n",
			want:    "WB.16.10.0012",
			backup:  "show run",
			arpComm: "show arp",
		},
		{
			name:    "juniper_junos",
			drv:     JuniperJunos{},
			cmd:     "show version",
			out:     "Hostname: ex4200\nModel: ex4200-48t\nJunos: 12.3R12-S15\n",
			want:    "12.3R12-S15",
			backup:  "show configuration | display set",
			arpComm: "show arp no-resolve",
		},
		{
			name:    "fortinet",
			drv:     Fortinet{},
			cmd:     "get system status",
			out:     "Version: FortiGate-VM64 v7.2.5,build1517,230615 (GA)\nSerial-Number: FGVM01",
			want:    "7.2.5",
			backup:  "show full-configuration",
			arpComm: "show arp",
		},
		{
			name:    "paloalto_panos",
			drv:     PaloAlto{},
			cmd:     "show system info",
			out:     "hostname: PA-VM\nsw-version: 10.2.3\nmodel: PA-VM",
			want:    "10.2.3",
			backup:  "show config running",
			arpComm: "show arp all",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &fakeRunner{expect: c.cmd, out: c.out}
			if got := c.drv.GetVersion(r); got != c.want {
				t.Errorf("versione = %q, attesa %q", got, c.want)
			}
			if r.got != c.cmd {
				t.Errorf("comando inviato = %q, atteso %q", r.got, c.cmd)
			}
			if got := c.drv.BackupCommand(); got != c.backup {
				t.Errorf("comando backup = %q, atteso %q", got, c.backup)
			}
			if got := c.drv.ARPCommand(); got != c.arpComm {
				t.Errorf("comando ARP = %q, atteso %q", got, c.arpComm)
			}
		})
	}
}

// Il fallback JUNOS [..] scatta quando manca la forma "Junos: <ver>".
func TestJuniperFallbackPattern(t *testing.T) {
	r := &fakeRunner{expect: "show version", out: "JUNOS Base OS boot [9.6R1.13]"}
	if got := (JuniperJunos{}).GetVersion(r); got != "9.6R1.13" {
		t.Errorf("versione = %q, attesa %q", got, "9.6R1.13")
	}
}

// Output non riconosciuto → "Unknown", mai stringa vuota.
func TestUnknownWhenNoMatch(t *testing.T) {
	for name, d := range registry {
		r := &fakeRunner{expect: "nulla", out: ""}
		if got := d.GetVersion(r); got != "Unknown" {
			t.Errorf("%s: versione = %q, attesa %q", name, got, "Unknown")
		}
	}
}

func TestResolve(t *testing.T) {
	// 1. il campo driver del registro vendor ha la precedenza
	if d, ok := Resolve("qualsiasi", "hp_procurve"); !ok || d.BackupCommand() != "show run" {
		t.Error("driver esplicito non rispettato")
	}
	// 2. fallback per nome vendor
	if d, ok := Resolve("juniper", ""); !ok || d.BackupCommand() != "show configuration | display set" {
		t.Error("fallback per nome vendor non rispettato")
	}
	// 3. case/spazi irrilevanti
	if _, ok := Resolve("  CISCO  ", ""); !ok {
		t.Error("normalizzazione vendor non applicata")
	}
	// 4. vendor sconosciuto
	if _, ok := Resolve("acme", ""); ok {
		t.Error("vendor sconosciuto risolto per errore")
	}
	// 5. ResolveOrDefault ricade su cisco_ios
	if ResolveOrDefault("acme", "").BackupCommand() != "show running-config" {
		t.Error("ResolveOrDefault non ricade su cisco_ios")
	}
	// 6. cisco_9800 usa i comandi IOS
	if d, ok := Resolve("cisco_9800", ""); !ok || d.ARPCommand() != "show ip arp" {
		t.Error("cisco_9800 non mappato sul driver IOS")
	}
}

func TestIsFortinet(t *testing.T) {
	for _, v := range []string{"fortinet", "FortiGate", " fortios ", "fortiwifi"} {
		if !IsFortinet(v) {
			t.Errorf("%q non riconosciuto come Fortinet", v)
		}
	}
	for _, v := range []string{"cisco", "juniper", ""} {
		if IsFortinet(v) {
			t.Errorf("%q riconosciuto per errore come Fortinet", v)
		}
	}
}
