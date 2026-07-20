package provision

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Anche qui i golden vengono da security/provisioning_secrets.py eseguito
// davvero: il formato del placeholder e la forma del percorso sono un
// contratto verso la UI, che li mostra all'operatore.
func TestMaskSecretsMatchesPythonGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "secrets", "masked_input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}

	wantRaw, err := os.ReadFile(filepath.Join("testdata", "secrets", "masked_expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want any
	if err := json.Unmarshal(wantRaw, &want); err != nil {
		t.Fatal(err)
	}

	got := MaskSecrets(payload)

	// Confronto sul JSON normalizzato: le mappe Go non hanno ordine, e
	// marshalling con chiavi ordinate rende il confronto deterministico.
	gotJSON, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("mascheramento diverso dal Python.\nGo:\n%s\n\nPython:\n%s", gotJSON, wantJSON)
	}
}

// La config generata dal payload mascherato non deve contenere nessun
// segreto: è esattamente ciò che la UI mostra e fa scaricare (finding I-2).
func TestMaskedConfigMatchesPythonGoldenAndLeaksNothing(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "secrets", "masked_input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}

	masked, err := json.Marshal(MaskSecrets(payload))
	if err != nil {
		t.Fatal(err)
	}
	var cfg SwitchConfig
	if err := json.Unmarshal(masked, &cfg); err != nil {
		t.Fatal(err)
	}
	got := BuildConfig(cfg)

	wantRaw, err := os.ReadFile(filepath.Join("testdata", "secrets", "masked_config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ReplaceAll(string(wantRaw), "\r\n", "\n")
	if got != want {
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
	}

	// Il controllo che conta davvero: nessun segreto del payload originale
	// deve comparire nel testo consegnato all'operatore.
	for _, secret := range []string{"S3cr3t!", "En4ble!", "authpwd123", "privpwd123",
		"radkey1", "radkey2"} {
		if strings.Contains(got, secret) {
			t.Errorf("segreto %q in chiaro nella config mascherata", secret)
		}
	}
}

func TestIsSecretKey(t *testing.T) {
	for _, k := range []string{"password", "admin_password", "enable_secret", "auth_pass",
		"priv_pass", "psksecret", "aaa_key", "key", "SSH_PASSWORD"} {
		if !IsSecretKey(k) {
			t.Errorf("%q non riconosciuta come segreta", k)
		}
	}
	for _, k := range []string{"hostname", "mgmt_ip", "vlan", "admin_user", "role"} {
		if IsSecretKey(k) {
			t.Errorf("%q riconosciuta come segreta per errore", k)
		}
	}
}

// Un valore vuoto non va sostituito: nel Python non genera righe di config, e
// un placeholder al suo posto ne farebbe comparire di inesistenti.
func TestMaskSecretsLeavesEmptyAndNonStringAlone(t *testing.T) {
	in := map[string]any{
		"admin_password": "",
		"port_security":  true,
		"mgmt_vlan":      float64(99),
	}
	got, ok := MaskSecrets(in).(map[string]any)
	if !ok {
		t.Fatalf("MaskSecrets = %#v", MaskSecrets(in))
	}
	if got["admin_password"] != "" {
		t.Errorf("password vuota sostituita: %#v", got["admin_password"])
	}
	if got["port_security"] != true || got["mgmt_vlan"] != float64(99) {
		t.Errorf("valori non stringa alterati: %#v", got)
	}
}

// Il mascheramento non deve modificare il payload originale: il chiamante lo
// riusa per il push vero, che ha bisogno dei valori reali.
func TestMaskSecretsDoesNotMutateInput(t *testing.T) {
	in := map[string]any{
		"admin_password": "S3cr3t!",
		"snmpv3":         map[string]any{"auth_pass": "authpwd"},
		"aaa_servers":    []any{map[string]any{"key": "radkey"}},
	}
	MaskSecrets(in)

	if in["admin_password"] != "S3cr3t!" {
		t.Errorf("payload originale mutato: %#v", in["admin_password"])
	}
	if in["snmpv3"].(map[string]any)["auth_pass"] != "authpwd" {
		t.Error("mappa annidata mutata: il push userebbe un placeholder al posto del segreto")
	}
	if in["aaa_servers"].([]any)[0].(map[string]any)["key"] != "radkey" {
		t.Error("elemento di lista mutato")
	}
}
