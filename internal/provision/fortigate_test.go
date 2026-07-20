package provision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// I file in testdata/fortigate/ sono stati generati eseguendo davvero
// services/fortigate_provisioner.py dell'applicazione Python: ogni .json è
// l'input, il .txt omonimo l'output atteso.
//
// È la verifica che conta per questo package (stesso discorso di
// switch_test.go): la config generata finisce su firewall veri, e §1.3 del
// piano impone la parità 1:1 col Python. Non modificare né rigenerare questi
// golden da qui: vanno rigenerati solo rilanciando il Python, se e quando
// cambia.
func TestBuildFortiGateConfigMatchesPythonGolden(t *testing.T) {
	inputs, err := filepath.Glob("testdata/fortigate/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) == 0 {
		t.Fatal("nessun caso in testdata/fortigate/")
	}

	for _, in := range inputs {
		name := strings.TrimSuffix(filepath.Base(in), ".json")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(in)
			if err != nil {
				t.Fatal(err)
			}
			var cfg FortiGateConfig
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("input non decodificabile: %v", err)
			}
			wantRaw, err := os.ReadFile(filepath.Join("testdata", "fortigate", name+".txt"))
			if err != nil {
				t.Fatal(err)
			}
			// Normalizza CRLF -> LF: il repo ha core.autocrlf=true, quindi i
			// golden su disco Windows possono avere \r\n anche se generati
			// da un Python che scrive \n.
			want := strings.ReplaceAll(string(wantRaw), "\r\n", "\n")
			got := BuildFortiGateConfig(cfg)

			if got == want {
				return
			}
			// Riga per riga: su file lunghi (full_static_wan ha 130+ righe)
			// un diff testuale intero è illeggibile, si vuole solo la prima
			// riga che diverge.
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
					t.Fatalf("riga %d:\n  Go     = %q\n  Python = %q", i+1, g, w)
				}
			}
		})
	}
}

// I flag di sicurezza del Python hanno default True. In Go un campo assente
// nel JSON diventa false, che qui significherebbe disattivare in silenzio
// una protezione solo perché la UI non ha inviato la chiave: è la ragione
// per cui sono *bool.
func TestFortiGateSecurityFlagsDefaultOnWhenAbsent(t *testing.T) {
	var cfg FortiGateConfig
	if err := json.Unmarshal([]byte(`{"hostname":"FGT","lan_interface":"internal","lan_ip":"192.168.1.1","wan_interface":"wan1"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildFortiGateConfig(cfg)

	for _, want := range []string{
		"set strong-crypto enable",
		"set admin-lockout-threshold 3", // anti brute-force
		"set allowaccess ping\n",        // WAN senza accesso admin (ping soltanto)
		"set rest-api-set enable",
		"config firewall policy", // policy LAN->WAN attiva di default
	} {
		if !strings.Contains(got, want) {
			t.Errorf("protezione persa con chiave assente: manca %q", want)
		}
	}
}

// Un false esplicito deve però essere rispettato, altrimenti il default
// diventerebbe un valore imposto (vedi golden defaults_off).
func TestFortiGateSecurityFlagsRespectExplicitFalse(t *testing.T) {
	var cfg FortiGateConfig
	if err := json.Unmarshal([]byte(`{"hostname":"FGT","lockout":false,"strong_crypto":false,
		"lan_to_wan_policy":false,"disable_wan_admin":false,"rest_api_logging":false,
		"lan_interface":"internal","lan_ip":"192.168.1.1","wan_interface":"wan1"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildFortiGateConfig(cfg)

	for _, unwanted := range []string{
		"strong-crypto enable", "admin-lockout-threshold", "config firewall policy",
		"rest-api-set enable",
	} {
		if strings.Contains(got, unwanted) {
			t.Errorf("false esplicito ignorato: presente %q", unwanted)
		}
	}
	if !strings.Contains(got, "set allowaccess ping https ssh\n") {
		t.Error("disable_wan_admin=false ignorato: WAN ancora limitato al solo ping")
	}
}
