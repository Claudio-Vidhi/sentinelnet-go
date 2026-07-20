package provision

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
)

// La sequenza inviata in console è l'unica parte del percorso seriale
// verificabile senza hardware, ed è quella che conta: uno switch vergine
// riceve i comandi a tempo, senza prompt-matching, quindi l'ordine è tutto
// ciò che garantisce che finiscano nel contesto giusto.
func TestSerialScriptOrderAndFraming(t *testing.T) {
	steps := serialScript("hostname SW\n!\n! --- SEZIONE ---\nvlan 10\n")

	var lines []string
	for _, s := range steps {
		lines = append(lines, s.line)
	}
	want := []string{"", "enable", "configure terminal", "hostname SW", "vlan 10", "end", "write memory"}
	if len(lines) != len(want) {
		t.Fatalf("sequenza = %#v, attesa %#v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("passo %d = %q, atteso %q", i, lines[i], want[i])
		}
	}
}

// I commenti non sono comandi: inviarli in console li farebbe interpretare
// dalla CLI, che risponderebbe con un errore per ogni riga.
func TestSerialScriptDropsComments(t *testing.T) {
	for _, s := range serialScript("!\n! --- X ---\nhostname SW\n") {
		if strings.HasPrefix(strings.TrimSpace(s.line), "!") {
			t.Errorf("commento inviato in console: %q", s.line)
		}
	}
}

// Il salvataggio chiude sempre la sequenza: senza "write memory" la config
// sparisce al primo riavvio dello switch appena provisionato.
func TestSerialScriptAlwaysEndsWithSave(t *testing.T) {
	steps := serialScript("hostname SW\n")
	last := steps[len(steps)-1]
	if last.line != "write memory" {
		t.Errorf("ultimo passo = %q, atteso write memory", last.line)
	}
	if last.delay < time.Second {
		t.Errorf("pausa dopo il salvataggio = %v, troppo breve perché la scrittura in flash completi", last.delay)
	}
}

// Una config priva di comandi eseguibili non deve aprire nessuna connessione:
// non c'è niente da applicare.
func TestPushViaSSHRejectsEmptyConfig(t *testing.T) {
	res := PushViaSSH(context.Background(), "127.0.0.1", collect.Credentials{Username: "x"},
		"!\n! --- solo commenti ---\n", false)
	if res.Status != "error" {
		t.Errorf("status = %q, atteso error", res.Status)
	}
	if !strings.Contains(res.Message, "nessun comando") {
		t.Errorf("messaggio = %q", res.Message)
	}
}

// Un apparato irraggiungibile produce un errore strutturato, non un panic né
// un'attesa indefinita.
func TestPushViaSSHUnreachableHostIsError(t *testing.T) {
	done := make(chan PushResult, 1)
	go func() {
		done <- PushViaSSH(context.Background(), "127.0.0.1",
			collect.Credentials{Username: "x", Password: "y", Port: 1}, "hostname SW\n", false)
	}()

	select {
	case res := <-done:
		if res.Status != "error" {
			t.Errorf("status = %q, atteso error", res.Status)
		}
		if res.Message == "" {
			t.Error("errore senza messaggio: l'operatore non saprebbe cosa è andato storto")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("PushViaSSH non è tornato: connessione rifiutata dovrebbe fallire subito")
	}
}

// Una porta seriale inesistente è un errore riportato, non un panic.
func TestPushViaSerialUnknownPortIsError(t *testing.T) {
	res := PushViaSerial("COM_INESISTENTE_999", "hostname SW\n", 9600)
	if res.Status != "error" {
		t.Errorf("status = %q, atteso error", res.Status)
	}
	if !strings.Contains(res.Message, "COM_INESISTENTE_999") {
		t.Errorf("messaggio = %q, atteso citasse la porta", res.Message)
	}
}

// L'enumerazione è best-effort e non deve mai fallire: la UI si aspetta una
// lista, eventualmente vuota. Su un host senza porte COM il risultato è [].
func TestListSerialPortsNeverFails(t *testing.T) {
	if ports := ListSerialPorts(); ports == nil {
		t.Error("ListSerialPorts ha ritornato nil: la UI si aspetta una lista")
	}
}
