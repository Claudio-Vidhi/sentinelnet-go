package provision

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

// Consegna della config day-0: SSH su un apparato già raggiungibile, oppure
// console seriale per uno switch appena tolto dall'imballo, senza IP di
// management.
//
// Nessun rollback, in nessuno dei due percorsi (§7.4 del piano): il Python non
// ce l'ha e il port non lo inventa. Un push interrotto a metà lascia
// l'apparato configurato a metà; è un limite reale da dichiarare, non da
// nascondere.

// PushResult è l'esito di una consegna. Ricalca la forma del Python:
// {"status": "success", "output": ...} oppure {"status": "error", "message": ...}.
type PushResult struct {
	Status  string `json:"status"`
	Output  string `json:"output,omitempty"`
	Message string `json:"message,omitempty"`
	// Method e APIError valgono solo per il FortiGate, che ha due canali:
	// dicono quale ha funzionato e perché il primo non è bastato.
	Method   string `json:"method,omitempty"`
	APIError string `json:"api_error,omitempty"`
}

func pushError(format string, a ...any) PushResult {
	return PushResult{Status: "error", Message: fmt.Sprintf(format, a...)}
}

// PushViaSSH applica la configurazione su un apparato raggiungibile e,
// se richiesto, la salva in memoria non volatile.
//
// Il salvataggio fallito non annulla il push: la config è già applicata e
// attiva, e dirlo all'operatore è più utile che restituire un errore che
// suggerirebbe il contrario.
func PushViaSSH(ctx context.Context, host string, creds collect.Credentials,
	configText string, save bool) PushResult {

	commands := ConfigCommands(configText)
	if len(commands) == 0 {
		return pushError("nessun comando da applicare")
	}

	sess, err := collect.Dial(ctx, host, creds)
	if err != nil {
		return pushError("SSH %s: %v", host, err)
	}
	defer sess.Close()

	output := sess.RunConfig(commands)
	if save {
		output += "\n" + sess.Run("write memory")
	}
	return PushResult{Status: "success", Output: output}
}

// Ritmo della consegna seriale. La console non ha prompt affidabile su un
// apparato vergine, quindi si procede a tempo: nessun prompt-matching, come
// nel Python.
const (
	serialStepDelay    = 300 * time.Millisecond
	serialControlDelay = 500 * time.Millisecond
	serialSaveDelay    = time.Second
)

// serialStep è una riga da inviare in console con la pausa che la segue.
type serialStep struct {
	line  string
	delay time.Duration
}

// serialScript costruisce la sequenza completa inviata in console. È separata
// dall'I/O per poter essere verificata senza hardware: è l'unica parte del
// percorso seriale che si può testare in automatico.
func serialScript(configText string) []serialStep {
	steps := []serialStep{
		{"", serialControlDelay}, // sveglia la console e provoca il prompt
		{"enable", serialControlDelay},
		{"configure terminal", serialControlDelay},
	}
	for _, cmd := range ConfigCommands(configText) {
		steps = append(steps, serialStep{cmd, serialStepDelay})
	}
	return append(steps,
		serialStep{"end", serialControlDelay},
		serialStep{"write memory", serialSaveDelay},
	)
}

// PushViaSerial applica la configurazione via console/seriale (RS-232 o
// USB-to-serial), per il provisioning day-0 di uno switch senza rete.
func PushViaSerial(portName, configText string, baudrate int) PushResult {
	if baudrate == 0 {
		baudrate = 9600
	}
	port, err := serial.Open(portName, &serial.Mode{BaudRate: baudrate})
	if err != nil {
		return pushError("porta seriale %s: %v", portName, err)
	}
	defer port.Close()

	// Lettura non bloccante: senza timeout una console silenziosa bloccherebbe
	// la richiesta HTTP a tempo indeterminato.
	if err := port.SetReadTimeout(200 * time.Millisecond); err != nil {
		return pushError("porta seriale %s: %v", portName, err)
	}

	var log strings.Builder
	buf := make([]byte, 4096)
	for _, step := range serialScript(configText) {
		if _, err := port.Write([]byte(step.line + "\r\n")); err != nil {
			return pushError("scrittura su %s: %v", portName, err)
		}
		time.Sleep(step.delay)
		// L'eco della console è best-effort: serve all'operatore per capire
		// dove si è fermata, non al controllo di flusso.
		if n, err := port.Read(buf); err == nil && n > 0 {
			log.Write(buf[:n])
		}
	}
	return PushResult{Status: "success", Output: log.String()}
}

// SerialPort è una porta COM disponibile sull'host del server.
type SerialPort struct {
	Device      string `json:"device"`
	Description string `json:"description"`
}

// ListSerialPorts elenca le porte seriali dell'host. Best-effort: se
// l'enumerazione fallisce si ritorna una lista vuota, come nel Python — la UI
// mostra "nessuna porta" invece di un errore, ed è la stessa cosa per
// l'operatore.
func ListSerialPorts() []SerialPort {
	out := []SerialPort{}
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil {
		return out
	}
	for _, p := range ports {
		desc := p.Product
		if desc == "" {
			desc = p.Name
		}
		out = append(out, SerialPort{Device: p.Name, Description: desc})
	}
	return out
}
