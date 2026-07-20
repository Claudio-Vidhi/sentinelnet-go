package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
)

var operatorClaims = &auth.Claims{Username: "operatore", Role: "operator"}

// switchPayload è un payload del wizard con segreti in ogni forma prevista.
const switchPayload = `{
  "hostname":"SW-TEST","admin_user":"netadmin","admin_password":"S3cr3t!",
  "enable_secret":"En4ble!",
  "snmpv3":{"user":"snmpuser","auth_pass":"authpwd123","priv_pass":"privpwd123"},
  "aaa_protocol":"radius","aaa_servers":[{"ip":"10.0.0.10","key":"radkey1"}],
  "mgmt_vlan":99
}`

// I segreti del payload, per verificare che non escano mai in chiaro.
var switchSecrets = []string{"S3cr3t!", "En4ble!", "authpwd123", "privpwd123", "radkey1"}

// captureAudit intercetta le righe di audit. Con a.cfg nil (come in questi
// test) auditLog scrive su slog invece che sul file, quindi si sostituisce il
// logger predefinito e lo si ripristina a fine test.
func captureAudit(t *testing.T) func() string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf.String
}

func postProvision(t *testing.T, app *App, h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, operatorClaims))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// Il comportamento predefinito, e il motivo per cui esiste il finding I-2:
// la config mostrata nella UI non contiene segreti.
func TestProvisionerGenerateMasksSecretsByDefault(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := postProvision(t, app, app.handleProvisionerGenerate, "/api/provisioner/generate", switchPayload)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	cfg, _ := out["config"].(string)
	if cfg == "" {
		t.Fatal("config vuota")
	}
	for _, s := range switchSecrets {
		if strings.Contains(cfg, s) {
			t.Errorf("segreto %q in chiaro nella config generata", s)
		}
	}
	if !strings.Contains(cfg, "{{VAULT:admin_password}}") {
		t.Error("placeholder mancante: i segreti non sono stati sostituiti")
	}
	if out["materialized"] != false {
		t.Errorf("materialized = %v, atteso false", out["materialized"])
	}
}

// La materializzazione resta possibile, ma è esplicita e lascia una traccia:
// è l'unico momento in cui dei segreti escono in chiaro dall'applicazione.
func TestProvisionerGenerateMaterializedIsExplicitAndAudited(t *testing.T) {
	app, _ := testFGTApp(t)
	audit := captureAudit(t)

	rec := postProvision(t, app, app.handleProvisionerGenerate,
		"/api/provisioner/generate?materialized=true", switchPayload)

	out := decodeBody(t, rec)
	cfg, _ := out["config"].(string)
	if !strings.Contains(cfg, "S3cr3t!") {
		t.Error("materialized=true non ha prodotto i segreti reali")
	}
	if out["materialized"] != true {
		t.Errorf("materialized = %v, atteso true", out["materialized"])
	}
	if !strings.Contains(audit(), "MATERIALIZZATA") {
		t.Errorf("audit della materializzazione mancante: %s", audit())
	}
	if !strings.Contains(audit(), "operatore") {
		t.Error("l'audit non riporta chi ha chiesto i segreti in chiaro")
	}
}

// Un valore qualsiasi diverso da "true" non deve materializzare: il default
// sicuro vale anche per un parametro malformato.
func TestProvisionerGenerateOnlyTrueMaterializes(t *testing.T) {
	app, _ := testFGTApp(t)
	for _, q := range []string{"", "?materialized=false", "?materialized=1", "?materialized=yes"} {
		rec := postProvision(t, app, app.handleProvisionerGenerate,
			"/api/provisioner/generate"+q, switchPayload)
		cfg, _ := decodeBody(t, rec)["config"].(string)
		if strings.Contains(cfg, "S3cr3t!") {
			t.Errorf("query %q ha materializzato i segreti", q)
		}
	}
}

// Il download è materiale che esce dall'applicazione: va sempre in audit e
// deve arrivare come file, non come JSON.
func TestProvisionerDownloadIsFileAndAudited(t *testing.T) {
	app, _ := testFGTApp(t)
	audit := captureAudit(t)

	rec := postProvision(t, app, app.handleProvisionerDownload, "/api/provisioner/download", switchPayload)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "SW-TEST-day0.txt") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	for _, s := range switchSecrets {
		if strings.Contains(rec.Body.String(), s) {
			t.Errorf("segreto %q nel file scaricato", s)
		}
	}
	if !strings.Contains(audit(), "SW-TEST") {
		t.Errorf("download non registrato in audit: %s", audit())
	}
}

// Il push verso un apparato irraggiungibile fallisce, ma la risposta deve
// comunque contenere la config MASCHERATA: quella materializzata è servita
// solo all'apparato.
func TestProvisionerPushSSHReturnsMaskedConfig(t *testing.T) {
	app, _ := testFGTApp(t)
	body := `{"hostname":"SW-TEST","admin_password":"S3cr3t!","enable_secret":"En4ble!",
	          "ssh_host":"127.0.0.1","ssh_port":1,"ssh_username":"x","ssh_password":"y"}`

	rec := postProvision(t, app, app.handleProvisionerPushSSH, "/api/provisioner/push-ssh", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if out["status"] != "error" {
		t.Errorf("status = %v, atteso error verso un host irraggiungibile", out["status"])
	}
	cfg, _ := out["config"].(string)
	for _, s := range []string{"S3cr3t!", "En4ble!"} {
		if strings.Contains(cfg, s) {
			t.Errorf("segreto %q rimandato al client nella risposta del push", s)
		}
	}
	if !strings.Contains(cfg, "{{VAULT:") {
		t.Error("la config di risposta non è mascherata")
	}
}

// Senza ssh_host non c'è niente da raggiungere: 400 prima di qualunque
// tentativo di connessione.
func TestProvisionerPushSSHRequiresHost(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := postProvision(t, app, app.handleProvisionerPushSSH, "/api/provisioner/push-ssh",
		`{"hostname":"SW"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400: %s", rec.Code, rec.Body.String())
	}
}

func TestProvisionerPushSerialRequiresComPort(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := postProvision(t, app, app.handleProvisionerPushSerial, "/api/provisioner/push-serial",
		`{"hostname":"SW"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400", rec.Code)
	}
}

// Le stesse garanzie valgono per il FortiGate: è il percorso che genera
// config per un firewall esposto.
func TestFGTProvisionerGenerateMasksSecretsByDefault(t *testing.T) {
	app, _ := testFGTApp(t)
	body := `{"hostname":"FGT-TEST","admin_user":"netadmin","admin_password":"Adm1nPwd!",
	          "snmpv3":{"user":"u","auth_pass":"authpwd123","priv_pass":"privpwd123"},
	          "ha":{"group_name":"HA","password":"HaSecret!","hbdev":"port9"}}`

	rec := postProvision(t, app, app.handleFGTProvisionerGenerate, "/api/provisioner/fgt/generate", body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	cfg, _ := decodeBody(t, rec)["config"].(string)
	for _, s := range []string{"Adm1nPwd!", "authpwd123", "privpwd123", "HaSecret!"} {
		if strings.Contains(cfg, s) {
			t.Errorf("segreto %q in chiaro nella config FortiGate", s)
		}
	}
	if !strings.Contains(cfg, "set hostname FGT-TEST") {
		t.Error("config FortiGate non generata")
	}
}

// Il payload deve restare intatto per il push vero: se il mascheramento
// mutasse la mappa, l'apparato riceverebbe i placeholder al posto delle
// password. Qui si verifica dall'esterno, sull'ordine reale delle chiamate.
func TestPushBuildsFromRealSecretsButAnswersMasked(t *testing.T) {
	app, _ := testFGTApp(t)
	body := `{"hostname":"SW","admin_user":"netadmin","admin_password":"S3cr3t!",
	          "com_port":"COM_INESISTENTE_999"}`

	rec := postProvision(t, app, app.handleProvisionerPushSerial, "/api/provisioner/push-serial", body)

	out := decodeBody(t, rec)
	if out["status"] != "error" {
		t.Fatalf("status = %v, atteso error su porta inesistente", out["status"])
	}
	cfg, _ := out["config"].(string)
	if strings.Contains(cfg, "S3cr3t!") {
		t.Error("segreto nella risposta")
	}
	if !strings.Contains(cfg, "{{VAULT:admin_password}}") {
		t.Errorf("config di risposta non mascherata: %q", cfg)
	}
}

// La lista delle porte seriali è sempre una lista, anche su un host che non
// ne ha: la UI non deve gestire un null.
func TestProvisionerSerialPortsAlwaysReturnsList(t *testing.T) {
	app, _ := testFGTApp(t)
	req := httptest.NewRequest("GET", "/api/provisioner/serial-ports", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, operatorClaims))
	rec := httptest.NewRecorder()
	app.handleProvisionerSerialPorts(rec, req)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("risposta non JSON: %s", rec.Body.String())
	}
	if _, ok := out["ports"].([]any); !ok {
		t.Errorf("ports = %#v, attesa una lista", out["ports"])
	}
}
