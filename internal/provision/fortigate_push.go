package provision

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fortigate"
	"go.bug.st/serial"
)

// Consegna della config day-0 FortiOS. Tre canali, come nel Python: REST API
// col token salvato, SSH, console seriale.
//
// FortiOS differisce dallo switch Cisco su due punti che qui contano:
// il commento è '#' e non '!', e la configurazione è salvata automaticamente a
// ogni 'end' — quindi niente "write memory" e niente "configure terminal"
// attorno al blocco, che nel testo generato è già presente nella forma
// 'config ... end'.

// FortiOSCommands riduce la config alle sole righe eseguibili. Il commento
// FortiOS è '#': usare il filtro dello switch lascerebbe passare i commenti,
// che la CLI rifiuterebbe uno per uno.
func FortiOSCommands(configText string) []string {
	var out []string
	for _, ln := range strings.Split(configText, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// PushFortiGateViaAPI carica la config come config-script tramite la REST API.
// È il canale preferito quando esiste un token per l'host: non dipende dal
// prompt CLI, che su un apparato vergine è il punto più fragile.
func PushFortiGateViaAPI(ctx context.Context, c *fortigate.Client, configText, filename string) PushResult {
	if filename == "" {
		filename = "sentinelnet-day0"
	}
	body := map[string]string{
		"filename":     filename,
		"file_content": base64.StdEncoding.EncodeToString([]byte(configText)),
	}
	data, err := c.Post(ctx, "monitor/system/config-script/upload", body, nil)
	if err != nil {
		return pushError("%v", err)
	}
	// Il campo status manca quando la chiamata è andata a buon fine senza
	// corpo strutturato: l'assenza vale "success", come nel Python.
	if s, ok := data["status"].(string); ok && s != "success" {
		return pushError("config-script upload: %v", data)
	}
	out, _ := json.MarshalIndent(data, "", " ")
	return PushResult{Status: "success", Output: string(out)}
}

// PushFortiGateViaSSH applica la config via SSH. Le righe sono inviate così
// come sono: il testo contiene già i propri 'config'/'end', quindi non va
// avvolto in una sessione di configurazione come per lo switch.
func PushFortiGateViaSSH(ctx context.Context, host string, creds collect.Credentials,
	configText string) PushResult {

	commands := FortiOSCommands(configText)
	if len(commands) == 0 {
		return pushError("nessun comando da applicare")
	}

	sess, err := collect.Dial(ctx, host, creds)
	if err != nil {
		return pushError("SSH %s: %v", host, err)
	}
	defer sess.Close()

	var out strings.Builder
	for _, cmd := range commands {
		out.WriteString(sess.Run(cmd))
	}
	// Nessun "write memory": FortiOS salva a ogni 'end'.
	return PushResult{Status: "success", Output: out.String()}
}

// Ritmo della console FortiOS: più lento di quello dello switch, perché il
// login iniziale su un'unità vergine passa dalla richiesta di impostare una
// password.
const (
	fgtSerialStepDelay = 400 * time.Millisecond
	fgtSerialUserDelay = 600 * time.Millisecond
	fgtSerialPassDelay = 800 * time.Millisecond
)

// fortiGateSerialScript costruisce la sequenza inviata in console: login e poi
// i comandi. Separata dall'I/O per essere verificabile senza hardware.
func fortiGateSerialScript(configText, username, password string) []serialStep {
	if username == "" {
		username = "admin"
	}
	steps := []serialStep{
		{"", fgtSerialUserDelay}, // provoca il prompt di login
		{username, fgtSerialUserDelay},
		// La password vuota è normale su un'unità vergine: FortiOS chiede di
		// impostarla al primo accesso. Si invia comunque la riga, altrimenti
		// il prompt resta in attesa.
		{password, fgtSerialPassDelay},
	}
	for _, cmd := range FortiOSCommands(configText) {
		steps = append(steps, serialStep{cmd, fgtSerialStepDelay})
	}
	return steps
}

// PushFortiGateViaSerial applica la config via console per il day-0 di un
// FortiGate vergine.
func PushFortiGateViaSerial(portName, configText string, baudrate int,
	username, password string) PushResult {

	if baudrate == 0 {
		baudrate = 9600
	}
	port, err := serial.Open(portName, &serial.Mode{BaudRate: baudrate})
	if err != nil {
		return pushError("porta seriale %s: %v", portName, err)
	}
	defer port.Close()

	if err := port.SetReadTimeout(200 * time.Millisecond); err != nil {
		return pushError("porta seriale %s: %v", portName, err)
	}

	var log strings.Builder
	buf := make([]byte, 4096)
	for _, step := range fortiGateSerialScript(configText, username, password) {
		if _, err := port.Write([]byte(step.line + "\r\n")); err != nil {
			return pushError("scrittura su %s: %v", portName, err)
		}
		time.Sleep(step.delay)
		if n, err := port.Read(buf); err == nil && n > 0 {
			log.Write(buf[:n])
		}
	}
	return PushResult{Status: "success", Output: log.String()}
}
