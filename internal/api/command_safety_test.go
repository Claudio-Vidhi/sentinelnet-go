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
