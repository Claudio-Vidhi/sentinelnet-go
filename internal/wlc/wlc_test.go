package wlc

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recorder cattura i comandi eseguiti e risponde sempre allo stesso modo.
func recorder(out string) (Runner, *[]string) {
	var seen []string
	return func(ctx context.Context, p Platform, command string) (string, error) {
		seen = append(seen, command)
		return out, nil
	}, &seen
}

func TestPlatformOf(t *testing.T) {
	cases := map[string]Platform{
		"cisco_wlc":  AireOS,
		"CISCO_WLC":  AireOS,
		"cisco_9800": IOSXE,
		"cisco":      IOSXE,
		"":           IOSXE, // il generico ricade su IOS-XE
	}
	for vendor, want := range cases {
		if got := PlatformOf(vendor); got != want {
			t.Errorf("PlatformOf(%q) = %q, atteso %q", vendor, got, want)
		}
	}
}

// AireOS non conosce "terminal length 0": usarlo lascerebbe la paginazione
// attiva e gli output lunghi troncati al primo "--More--".
func TestPagingCommandPerPlatform(t *testing.T) {
	if got := AireOS.PagingCommand(); got != "config paging disable" {
		t.Errorf("paging AireOS = %q", got)
	}
	if got := IOSXE.PagingCommand(); got != "terminal length 0" {
		t.Errorf("paging IOS-XE = %q", got)
	}
}

// Lo stesso servizio si traduce in comandi diversi sulle due famiglie.
func TestQueryPicksPlatformCommand(t *testing.T) {
	for _, tc := range []struct{ vendor, service, want string }{
		{"cisco_wlc", "status", "show sysinfo"},
		{"cisco_9800", "status", "show wireless summary"},
		{"cisco_wlc", "client_summary", "show client summary"},
		{"cisco", "client_summary", "show wireless client summary"},
		{"cisco_wlc", "rogue_aps", "show rogue ap summary"},
		{"cisco_9800", "interfaces", "show ip interface brief"},
	} {
		run, seen := recorder("output")
		res, err := Query(context.Background(), run, tc.vendor, tc.service, "")
		if err != nil {
			t.Fatalf("%s/%s: %v", tc.vendor, tc.service, err)
		}
		if res.Command != tc.want {
			t.Errorf("%s/%s comando = %q, atteso %q", tc.vendor, tc.service, res.Command, tc.want)
		}
		if len(*seen) != 1 || (*seen)[0] != tc.want {
			t.Errorf("comandi eseguiti = %v", *seen)
		}
		if res.Data != "output" {
			t.Errorf("data = %q", res.Data)
		}
	}
}

// Il MAC va sostituito nel comando già normalizzato, qualunque notazione
// abbia usato il chiamante.
func TestQuerySubstitutesNormalizedMAC(t *testing.T) {
	run, _ := recorder("")
	res, err := Query(context.Background(), run, "cisco_wlc", "client_detail", "AABB.CCDD.EEFF")
	if err != nil {
		t.Fatal(err)
	}
	if res.Command != "show client detail aa:bb:cc:dd:ee:ff" {
		t.Errorf("comando = %q", res.Command)
	}
}

func TestQueryRejectsUnknownService(t *testing.T) {
	run, seen := recorder("")
	if _, err := Query(context.Background(), run, "cisco", "show_everything", ""); err == nil {
		t.Fatal("servizio sconosciuto accettato")
	}
	if len(*seen) != 0 {
		t.Errorf("comando eseguito per un servizio sconosciuto: %v", *seen)
	}
}

// Un MAC mancante o malformato non deve mai raggiungere la riga di comando.
func TestQueryRejectsBadMACBeforeRunning(t *testing.T) {
	for _, mac := range []string{"", "non-un-mac", "aa:bb:cc:dd:ee", "zz:bb:cc:dd:ee:ff"} {
		run, seen := recorder("")
		if _, err := Query(context.Background(), run, "cisco_wlc", "client_detail", mac); err == nil {
			t.Errorf("MAC %q accettato", mac)
		}
		if len(*seen) != 0 {
			t.Errorf("MAC %q: comando eseguito comunque (%v)", mac, *seen)
		}
	}
}

func TestNormalizeMAC(t *testing.T) {
	for _, in := range []string{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF",
		"aabb.ccdd.eeff", "aabbccddeeff", " aa:bb:cc:dd:ee:ff "} {
		got, err := NormalizeMAC(in)
		if err != nil {
			t.Errorf("NormalizeMAC(%q): %v", in, err)
			continue
		}
		if got != "aa:bb:cc:dd:ee:ff" {
			t.Errorf("NormalizeMAC(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "10.0.0.1", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00"} {
		if _, err := NormalizeMAC(in); err == nil {
			t.Errorf("NormalizeMAC(%q) non ha segnalato l'errore", in)
		}
	}
}

func TestIsWLCVendor(t *testing.T) {
	for _, v := range []string{"cisco_wlc", "cisco_9800", "cisco", "CISCO"} {
		if !IsWLCVendor(v) {
			t.Errorf("%q rifiutato", v)
		}
	}
	for _, v := range []string{"fortinet", "hp", "", "cisco_asa"} {
		if IsWLCVendor(v) {
			t.Errorf("%q accettato", v)
		}
	}
}

// La diagnosi raccoglie quattro sezioni e non fallisce in blocco se una
// cede: è il suo scopo.
func TestDiagnoseWifiClientIsolatesSectionErrors(t *testing.T) {
	run := func(ctx context.Context, p Platform, command string) (string, error) {
		if strings.Contains(command, "rogue") {
			return "", errors.New("comando non supportato")
		}
		return "output di " + command, nil
	}

	d := DiagnoseWifiClient(context.Background(), run, "10.0.0.1", "cisco_wlc", "aa:bb:cc:dd:ee:ff")

	if d.WLC != "10.0.0.1" || d.ClientMAC != "aa:bb:cc:dd:ee:ff" || d.Platform != "aireos" {
		t.Errorf("intestazione inattesa: %+v", d)
	}
	for _, name := range []string{"client_detail", "ap_summary", "wlan_summary", "rogue_aps"} {
		if _, ok := d.Sections[name]; !ok {
			t.Errorf("sezione %q mancante", name)
		}
	}
	if _, ok := d.Sections["client_detail"].(Result); !ok {
		t.Errorf("client_detail = %#v, attesa una Result", d.Sections["client_detail"])
	}
	sec, ok := d.Sections["rogue_aps"].(map[string]string)
	if !ok || sec["error"] == "" {
		t.Errorf("rogue_aps = %#v, attesa una sezione con errore", d.Sections["rogue_aps"])
	}
}

// Un MAC malformato non impedisce di raccogliere le sezioni che non ne hanno
// bisogno: l'operatore vede comunque AP, WLAN e rogue.
func TestDiagnoseWifiClientBadMACStillCollectsRest(t *testing.T) {
	run, _ := recorder("ok")
	d := DiagnoseWifiClient(context.Background(), run, "10.0.0.1", "cisco", "non-un-mac")

	if sec, ok := d.Sections["client_detail"].(map[string]string); !ok || sec["error"] == "" {
		t.Errorf("client_detail = %#v, atteso un errore", d.Sections["client_detail"])
	}
	if _, ok := d.Sections["ap_summary"].(Result); !ok {
		t.Errorf("ap_summary = %#v, attesa una Result", d.Sections["ap_summary"])
	}
}
