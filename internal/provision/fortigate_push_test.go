package provision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fortigate"
)

// Il commento FortiOS è '#', non '!': con il filtro dello switch i commenti
// passerebbero e la CLI li rifiuterebbe uno per uno.
func TestFortiOSCommandsStripsHashComments(t *testing.T) {
	cmds := FortiOSCommands("# --- SEZIONE ---\nconfig system global\n    set hostname FGT\nend\n\n")
	want := []string{"config system global", "    set hostname FGT", "end"}
	if len(cmds) != len(want) {
		t.Fatalf("comandi = %#v, attesi %#v", cmds, want)
	}
	for i := range want {
		if cmds[i] != want[i] {
			t.Errorf("comando %d = %q, atteso %q", i, cmds[i], want[i])
		}
	}
}

// Il '!' non è un commento in FortiOS: scartarlo nasconderebbe un comando.
func TestFortiOSCommandsKeepsBangLines(t *testing.T) {
	cmds := FortiOSCommands("!strano ma non un commento\n")
	if len(cmds) != 1 {
		t.Fatalf("comandi = %#v", cmds)
	}
}

// La sequenza console apre con il login e prosegue con i comandi: su
// un'unità vergine il prompt chiede utente e password prima di tutto.
func TestFortiGateSerialScriptStartsWithLogin(t *testing.T) {
	steps := fortiGateSerialScript("config system global\nend\n", "", "")

	if steps[0].line != "" || steps[1].line != "admin" {
		t.Errorf("login = %q/%q, atteso vuoto poi admin (default)", steps[0].line, steps[1].line)
	}
	if steps[2].line != "" {
		t.Errorf("password = %q, attesa vuota su unità vergine", steps[2].line)
	}
	last := steps[len(steps)-1]
	if last.line != "end" {
		t.Errorf("ultimo comando = %q, atteso end", last.line)
	}
	// Nessun "write memory": FortiOS salva a ogni 'end', e inviarlo
	// produrrebbe un errore di comando sconosciuto.
	for _, s := range steps {
		if strings.Contains(s.line, "write memory") {
			t.Error("write memory inviato a un FortiOS")
		}
	}
}

func TestFortiGateSerialScriptUsesGivenCredentials(t *testing.T) {
	steps := fortiGateSerialScript("end\n", "netadmin", "Pwd!")
	if steps[1].line != "netadmin" || steps[2].line != "Pwd!" {
		t.Errorf("credenziali = %q/%q", steps[1].line, steps[2].line)
	}
}

// La REST API riceve la config come config-script in base64: è il canale
// preferito perché non dipende dal prompt CLI.
func TestPushFortiGateViaAPIUploadsBase64Script(t *testing.T) {
	var gotPath string
	var body map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer srv.Close()

	res := PushFortiGateViaAPI(context.Background(), clientFor(t, srv.URL),
		"config system global\nend\n", "")
	if res.Status != "success" {
		t.Fatalf("status = %q, messaggio = %q", res.Status, res.Message)
	}
	if !strings.Contains(gotPath, "config-script/upload") {
		t.Errorf("path = %q", gotPath)
	}
	enc, _ := body["file_content"].(string)
	decoded, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("file_content non è base64 valido: %v", err)
	}
	if !strings.Contains(string(decoded), "config system global") {
		t.Errorf("config caricata = %q", decoded)
	}
	if body["filename"] != "sentinelnet-day0" {
		t.Errorf("filename = %v, atteso il default", body["filename"])
	}
}

// Uno status diverso da success è un errore riportato, non un falso positivo:
// l'apparato ha risposto, ma non ha applicato niente.
func TestPushFortiGateViaAPIReportsNonSuccessStatus(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","message":"script non valido"}`))
	}))
	defer srv.Close()

	res := PushFortiGateViaAPI(context.Background(), clientFor(t, srv.URL), "end\n", "")
	if res.Status != "error" {
		t.Errorf("status = %q, atteso error", res.Status)
	}
}

func TestPushFortiGateViaSerialUnknownPortIsError(t *testing.T) {
	res := PushFortiGateViaSerial("COM_INESISTENTE_999", "end\n", 9600, "admin", "")
	if res.Status != "error" {
		t.Errorf("status = %q, atteso error", res.Status)
	}
}

// clientFor costruisce un client REST che punta al server di test.
func clientFor(t *testing.T, rawURL string) *fortigate.Client {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	return fortigate.New(u.Hostname(), port, "token", false)
}
