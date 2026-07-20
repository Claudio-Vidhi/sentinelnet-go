package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
)

func TestIsCommandSafe(t *testing.T) {
	cases := []struct {
		cmd  string
		safe bool
	}{
		{"show run", true},
		{"show mac address-table", true},
		{"reload", false},
		{"  RELOAD  ", false},
		{"erase startup-config", false},
		{"format flash:", false},
		{"reboot", false},
		{"conf t", false},
		{"configure terminal", false},
		{"copy running-config startup-config", false},
		{"copy tftp://1.2.3.4/x startup-config", false},
		{"copy running-config tftp://1.2.3.4/x", true}, // non tocca la startup-config
		{"show reloadstats", true},                     // \breload\b non deve matchare parole più lunghe
		{"interface gi0/1", true},
	}
	for _, c := range cases {
		if got := isCommandSafe(c.cmd); got != c.safe {
			t.Errorf("isCommandSafe(%q) = %v, want %v", c.cmd, got, c.safe)
		}
	}
}

var destructiveCmds = []string{"reload", "erase startup-config", "write erase",
	"format flash:", "delete flash:file", "reboot"}

// Un admin bypassa la blacklist (command_allowed del Python, audit M-1): è il
// ruolo che deve poter riavviare un apparato.
func TestCommandAllowedAdminBypasses(t *testing.T) {
	app, _ := testFGTApp(t)
	admin := &auth.Claims{Username: "admin", Role: "admin"}
	for _, cmd := range destructiveCmds {
		if !app.commandAllowed(cmd, admin) {
			t.Errorf("admin bloccato su %q", cmd)
		}
	}
}

// Un operatore no, finché l'impostazione è attiva (default).
func TestCommandAllowedOperatorBlockedByDefault(t *testing.T) {
	app, _ := testFGTApp(t)
	op := &auth.Claims{Username: "operatore", Role: "operator"}
	for _, cmd := range destructiveCmds {
		if app.commandAllowed(cmd, op) {
			t.Errorf("operatore autorizzato su %q senza aver disattivato l'impostazione", cmd)
		}
	}
	if !app.commandAllowed("show version", op) {
		t.Error("comando innocuo bloccato")
	}
}

// Disattivando l'impostazione gli operatori passano: è il senso della chiave.
func TestCommandAllowedOperatorWhenSettingDisabled(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.SetSetting(cliBlacklistOperatorsKey, "false"); err != nil {
		t.Fatal(err)
	}
	op := &auth.Claims{Username: "operatore", Role: "operator"}
	if !app.commandAllowed("reload", op) {
		t.Error("operatore ancora bloccato con l'impostazione disattivata")
	}
}

// Una chiave assente, vuota o malformata NON deve disattivare la protezione:
// solo il valore esplicito "false" la spegne.
func TestBlacklistStaysOnForMalformedSetting(t *testing.T) {
	app, st := testFGTApp(t)
	op := &auth.Claims{Username: "operatore", Role: "operator"}
	for _, v := range []string{"", "no", "0", "False", "vero", "true"} {
		if err := st.SetSetting(cliBlacklistOperatorsKey, v); err != nil {
			t.Fatal(err)
		}
		if app.commandAllowed("reload", op) {
			t.Errorf("impostazione %q ha disattivato la blacklist", v)
		}
	}
}

// L'invio massivo non ha bypass per nessuno: il comando parte verso decine di
// apparati insieme, quindi un errore non si ferma al primo.
func TestBulkDestructiveHasNoBypass(t *testing.T) {
	for _, cmd := range []string{"reload", "reboot", "erase startup-config",
		"format flash:", "write erase"} {
		if isBulkCommandAllowed(cmd) {
			t.Errorf("comando distruttivo %q ammesso nell'invio massivo", cmd)
		}
	}
	for _, cmd := range []string{"show version", "show running-config"} {
		if !isBulkCommandAllowed(cmd) {
			t.Errorf("comando innocuo %q bloccato nell'invio massivo", cmd)
		}
	}
}

// La rotta massiva deve rifiutare prima di toccare qualunque apparato, anche
// per un admin.
func TestHandleBulkCommandRejectsDestructiveEvenForAdmin(t *testing.T) {
	app, _ := testFGTApp(t)
	audit := captureAudit(t)

	req := httptest.NewRequest("POST", "/api/bulk-command",
		strings.NewReader(`{"ips":["10.0.0.1"],"commands":"show version\nreload","mode":"exec"}`))
	req = withIPParam(req, "10.0.0.1", adminClaims)
	rec := httptest.NewRecorder()
	app.handleBulkCommand(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, atteso 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(audit(), "Invio massivo bloccato") {
		t.Errorf("blocco non registrato in audit: %s", audit())
	}
}

func TestBypassNote(t *testing.T) {
	if got := bypassNote(&auth.Claims{Role: "admin"}); !strings.Contains(got, "admin") {
		t.Errorf("nota admin = %q", got)
	}
	if got := bypassNote(&auth.Claims{Role: "operator"}); !strings.Contains(got, "operatori") {
		t.Errorf("nota operatore = %q", got)
	}
}

// La rotta che la UI usa per la checkbox deve esistere e riflettere lo stato
// reale: senza, l'impostazione sarebbe irraggiungibile e la UI mentirebbe.
func TestCliBlacklistSettingsRoundTrip(t *testing.T) {
	app, _ := testFGTApp(t)
	audit := captureAudit(t)

	// Default: attiva.
	rec := httptest.NewRecorder()
	app.handleGetCliBlacklistSettings(rec, httptest.NewRequest("GET", "/api/settings/cli-blacklist", nil))
	if got := decodeBody(t, rec)["cli_blacklist_operators"]; got != true {
		t.Errorf("stato iniziale = %v, attesa attiva", got)
	}

	// Disattivazione.
	req := httptest.NewRequest("POST", "/api/settings/cli-blacklist",
		strings.NewReader(`{"cli_blacklist_operators":false}`))
	req = withIPParam(req, "", adminClaims)
	rec = httptest.NewRecorder()
	app.handleSetCliBlacklistSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(audit(), "disattivata") {
		t.Errorf("cambio di postura non registrato in audit: %s", audit())
	}

	// Rilettura: ora un operatore passa.
	rec = httptest.NewRecorder()
	app.handleGetCliBlacklistSettings(rec, httptest.NewRequest("GET", "/api/settings/cli-blacklist", nil))
	if got := decodeBody(t, rec)["cli_blacklist_operators"]; got != false {
		t.Errorf("stato dopo la disattivazione = %v", got)
	}
	if !app.commandAllowed("reload", &auth.Claims{Username: "op", Role: "operator"}) {
		t.Error("l'impostazione salvata dalla rotta non ha effetto su commandAllowed")
	}
}

// La tab FortiGate LIVE è in preview: solo un "true" esplicito la accende,
// al contrario della blacklist che è attiva per default.
func TestFortigatePreviewDefaultsOff(t *testing.T) {
	app, _ := testFGTApp(t)

	rec := httptest.NewRecorder()
	app.handleGetFortigatePreviewSettings(rec, httptest.NewRequest("GET", "/api/settings/fortigate-preview", nil))
	if got := decodeBody(t, rec)["fortigate_preview"]; got != false {
		t.Errorf("stato iniziale = %v, attesa disattivata", got)
	}

	req := httptest.NewRequest("POST", "/api/settings/fortigate-preview",
		strings.NewReader(`{"enabled":true}`))
	req = withIPParam(req, "", adminClaims)
	rec = httptest.NewRecorder()
	app.handleSetFortigatePreviewSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	app.handleGetFortigatePreviewSettings(rec, httptest.NewRequest("GET", "/api/settings/fortigate-preview", nil))
	if got := decodeBody(t, rec)["fortigate_preview"]; got != true {
		t.Errorf("stato dopo l'attivazione = %v", got)
	}
}

// La porta impostata da /api/settings/app deve essere davvero letta all'avvio,
// altrimenti sarebbe un campo che mente.
func TestAppSettingsPortIsHonouredAtStartup(t *testing.T) {
	app, _ := testFGTApp(t)
	t.Setenv("SENTINELNET_PORT", "")
	t.Setenv("SENTINELNET_HOST", "")

	if addr := app.ResolveListenAddr(); !strings.HasSuffix(addr, ":8000") {
		t.Errorf("addr di default = %q, attesa la porta 8000", addr)
	}

	req := httptest.NewRequest("POST", "/api/settings/app", strings.NewReader(`{"port":9443}`))
	req = withIPParam(req, "", adminClaims)
	rec := httptest.NewRecorder()
	app.handleSetAppSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}

	if addr := app.ResolveListenAddr(); !strings.HasSuffix(addr, ":9443") {
		t.Errorf("addr = %q, la porta salvata non viene letta all'avvio", addr)
	}
}

// L'ambiente vince sul valore salvato: è il modo in cui si forza la porta in
// un container, e non deve dipendere dal database.
func TestAppSettingsEnvWinsOverStoredPort(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.SetSetting(appPortSettingKey, "9443"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINELNET_PORT", "7000")
	t.Setenv("SENTINELNET_HOST", "")

	if addr := app.ResolveListenAddr(); !strings.HasSuffix(addr, ":7000") {
		t.Errorf("addr = %q, l'ambiente deve vincere", addr)
	}
}

// Una chiave che il Go non onora è rifiutata invece di essere ignorata: se la
// UI prova a impostare un certificato TLS, l'operatore deve saperlo subito.
func TestAppSettingsRejectsUnsupportedKeys(t *testing.T) {
	app, _ := testFGTApp(t)
	for _, body := range []string{
		`{"ssl_certfile":"/etc/cert.pem"}`,
		`{"cors_origins":"*"}`,
		`{"no_browser":true}`,
		`{"retention_flows_days":10}`,
	} {
		req := httptest.NewRequest("POST", "/api/settings/app", strings.NewReader(body))
		req = withIPParam(req, "", adminClaims)
		rec := httptest.NewRecorder()
		app.handleSetAppSettings(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s -> status %d, atteso 400", body, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Invalid key") {
			t.Errorf("body %s -> messaggio %q", body, rec.Body.String())
		}
	}
}

func TestAppSettingsValidatesPortRange(t *testing.T) {
	app, _ := testFGTApp(t)
	for _, body := range []string{`{"port":0}`, `{"port":70000}`, `{"port":-1}`, `{"port":"abc"}`} {
		req := httptest.NewRequest("POST", "/api/settings/app", strings.NewReader(body))
		req = withIPParam(req, "", adminClaims)
		rec := httptest.NewRecorder()
		app.handleSetAppSettings(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s -> status %d, atteso 400", body, rec.Code)
		}
	}
}

// Valore vuoto: si torna al default, cioè la porta salvata viene rimossa.
func TestAppSettingsEmptyValueResetsToDefault(t *testing.T) {
	app, st := testFGTApp(t)
	if err := st.SetSetting(appPortSettingKey, "9443"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SENTINELNET_PORT", "")
	t.Setenv("SENTINELNET_HOST", "")

	req := httptest.NewRequest("POST", "/api/settings/app", strings.NewReader(`{"port":""}`))
	req = withIPParam(req, "", adminClaims)
	rec := httptest.NewRecorder()
	app.handleSetAppSettings(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if addr := app.ResolveListenAddr(); !strings.HasSuffix(addr, ":8000") {
		t.Errorf("addr = %q, atteso il ritorno al default", addr)
	}
}
