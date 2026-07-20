package provision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// I file in testdata/ sono stati generati eseguendo davvero
// services/switch_provisioner.py dell'applicazione Python: ogni .json è
// l'input, il .txt omonimo l'output atteso.
//
// È la verifica che conta per questo package. Una running-config finisce su
// apparati veri, e §1.3 del piano impone la parità 1:1 col Python: una
// differenza "innocua" qui è una differenza di comportamento su uno switch in
// produzione. Rigenerare i golden solo se cambia il Python.
func TestBuildConfigMatchesPythonGolden(t *testing.T) {
	inputs, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatal("nessun caso in testdata/")
	}

	for _, in := range inputs {
		name := strings.TrimSuffix(filepath.Base(in), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			var cfg SwitchConfig
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("input non decodificabile: %v", err)
			}
			wantRaw, err := os.ReadFile(filepath.Join("testdata", name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			want := strings.ReplaceAll(string(wantRaw), "\r\n", "\n")
			got := BuildConfig(cfg)

			if got == want {
				return
			}
			// Riga per riga: su 60+ righe un diff testuale intero è illeggibile.
			gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
			for i := 0; i < len(gl) || i < len(wl); i++ {
				var g, w string
				if i < len(gl) {
					g = gl[i]
				}
				if i < len(wl) {
					w = wl[i]
				}
				if g != w {
					t.Errorf("riga %d:\n  Go     = %q\n  Python = %q", i+1, g, w)
				}
			}
		})
	}
}

// I flag di sicurezza del Python hanno default True. In Go un campo assente
// nel JSON diventa false, che qui significherebbe disattivare in silenzio una
// protezione solo perché la UI non ha inviato la chiave: è la ragione per cui
// sono *bool.
func TestSecurityFlagsDefaultOnWhenAbsent(t *testing.T) {
	var cfg SwitchConfig
	if err := json.Unmarshal([]byte(`{"hostname":"SW"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildConfig(cfg)

	for _, want := range []string{
		"no vstack", // Smart Install disabilitato
		"login block-for 120 attempts 5 within 60", // anti brute-force
		"spanning-tree portfast bpduguard default",
		"errdisable recovery cause bpduguard",
		"transport input ssh",
		"cdp run",
		"lldp run",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("protezione persa con chiave assente: manca %q", want)
		}
	}
	if strings.Contains(got, "transport input ssh telnet") {
		t.Error("telnet abilitato con ssh_only assente")
	}
}

// Un false esplicito deve però essere rispettato, altrimenti il default
// diventerebbe un valore imposto.
func TestSecurityFlagsRespectExplicitFalse(t *testing.T) {
	var cfg SwitchConfig
	if err := json.Unmarshal([]byte(`{"hostname":"SW","no_vstack":false,
		"login_block":false,"bpduguard":false,"ssh_only":false,
		"cdp_enabled":false,"lldp_enabled":false}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildConfig(cfg)

	for _, unwanted := range []string{
		"no vstack", "login block-for", "spanning-tree portfast bpduguard default",
	} {
		if strings.Contains(got, unwanted) {
			t.Errorf("false esplicito ignorato: presente %q", unwanted)
		}
	}
	for _, want := range []string{"no cdp run", "no lldp run", "transport input ssh telnet"} {
		if !strings.Contains(got, want) {
			t.Errorf("manca %q", want)
		}
	}
}

// La UI invia le VLAN sia come oggetto sia come solo id.
func TestVLANAcceptsBothNotations(t *testing.T) {
	var cfg SwitchConfig
	if err := json.Unmarshal([]byte(
		`{"hostname":"SW","vlans":[{"id":10,"name":"DATA"},20,{"id":30}]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildConfig(cfg)
	for _, want := range []string{"vlan 10\n name DATA", "vlan 20\n name VLAN20", "vlan 30\n name VLAN30"} {
		if !strings.Contains(got, want) {
			t.Errorf("manca %q", want)
		}
	}
}

// Una voce VLAN senza id non è utilizzabile e va scartata, non emessa come
// "vlan 0" — che su un apparato sarebbe un errore di configurazione.
func TestVLANWithoutIDIsDropped(t *testing.T) {
	var cfg SwitchConfig
	if err := json.Unmarshal([]byte(`{"hostname":"SW","vlans":[{"name":"ORFANA"},10]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildConfig(cfg)
	if strings.Contains(got, "vlan 0") || strings.Contains(got, "ORFANA") {
		t.Errorf("VLAN senza id non scartata:\n%s", got)
	}
	if !strings.Contains(got, "vlan 10") {
		t.Error("la VLAN valida è stata persa insieme a quella orfana")
	}
}

// ConfigCommands è ciò che viene inviato all'apparato: commenti e righe vuote
// non sono comandi.
func TestConfigCommandsStripsCommentsAndBlanks(t *testing.T) {
	cmds := ConfigCommands("hostname SW\n!\n! --- SEZIONE ---\n\n vlan 10\n")
	want := []string{"hostname SW", " vlan 10"}
	if len(cmds) != len(want) {
		t.Fatalf("comandi = %#v, attesi %#v", cmds, want)
	}
	for i := range want {
		if cmds[i] != want[i] {
			t.Errorf("comando %d = %q, atteso %q", i, cmds[i], want[i])
		}
	}
}

// L'indentazione dei sotto-comandi va conservata: "switchport mode access"
// senza lo spazio iniziale finirebbe nel contesto sbagliato.
func TestConfigCommandsKeepsIndentation(t *testing.T) {
	cmds := ConfigCommands("interface range Gi1/0/1\n switchport mode access\nexit\n")
	if cmds[1] != " switchport mode access" {
		t.Errorf("indentazione persa: %q", cmds[1])
	}
}
