// Package api: handler HTTP del provisioner day-0 — generazione, download e
// push della config per switch Cisco e FortiGate. Porta di routers/provisioner.py.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/provision"
)

// ---- helper interni ----

// provisionPayload è il payload del wizard nella sua forma generica. Serve
// grezzo perché il mascheramento dei segreti lavora sulle chiavi (finding
// I-2) e non sui campi tipizzati: vedi provision.MaskSecrets.
type provisionPayload map[string]any

func decodeProvisionPayload(r *http.Request) (provisionPayload, error) {
	var p provisionPayload
	if err := decodeJSON(r, &p); err != nil {
		return nil, err
	}
	if p == nil {
		p = provisionPayload{}
	}
	return p, nil
}

// str legge un campo stringa del payload, con default.
func (p provisionPayload) str(key, def string) string {
	if v, ok := p[key].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// buildSwitch e buildFortiGate ricostruiscono la config passando dalla forma
// tipizzata: il payload generico serve al mascheramento, la struct alla
// generazione.
func buildSwitch(p provisionPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	var cfg provision.SwitchConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	return provision.BuildConfig(cfg), nil
}

func buildFortiGate(p provisionPayload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	var cfg provision.FortiGateConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", err
	}
	return provision.BuildFortiGateConfig(cfg), nil
}

// masked applica il mascheramento dei segreti.
func masked(p provisionPayload) provisionPayload {
	m, _ := provision.MaskSecrets(map[string]any(p)).(map[string]any)
	return provisionPayload(m)
}

// provisionCfg prepara il payload per la generazione del testo (finding I-2):
// di default i segreti diventano placeholder {{VAULT:...}}; la
// materializzazione completa richiede un flag esplicito ed è auditata.
//
// L'audit della materializzazione non è un dettaglio: è l'unica traccia del
// momento in cui dei segreti sono usciti in chiaro dall'applicazione.
func (a *App) provisionCfg(r *http.Request, p provisionPayload, vendor string) provisionPayload {
	if r.URL.Query().Get("materialized") != "true" {
		return masked(p)
	}
	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf(
		"ATTENZIONE: config day-0 %s generata MATERIALIZZATA (segreti in chiaro) per '%s' da '%s'.",
		vendor, p.str("hostname", ""), claims.Username))
	return p
}

// writeConfigDownload risponde con la config come file .txt scaricabile.
func writeConfigDownload(w http.ResponseWriter, configText, filename string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write([]byte(configText))
}

// pushCreds estrae le credenziali SSH del push day-0 dal payload. L'apparato
// non è in inventario: le credenziali arrivano dal wizard, non dal vault.
func (p provisionPayload) pushCreds(userKey, passKey, secretKey string) (string, collect.Credentials) {
	host := p.str("ssh_host", "")
	port := 0
	if v, ok := p["ssh_port"].(float64); ok {
		port = int(v)
	}
	return host, collect.Credentials{
		Username:     p.str(userKey, ""),
		Password:     p.str(passKey, ""),
		EnableSecret: p.str(secretKey, ""),
		Port:         port,
	}
}

func (p provisionPayload) boolOr(key string, def bool) bool {
	if v, ok := p[key].(bool); ok {
		return v
	}
	return def
}

func (p provisionPayload) intOr(key string, def int) int {
	if v, ok := p[key].(float64); ok && v != 0 {
		return int(v)
	}
	return def
}

// ---- switch Cisco ----

// handleProvisionerGenerate: POST /api/provisioner/generate — testo della
// config per view/copy nella UI.
func (a *App) handleProvisionerGenerate(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	materialized := r.URL.Query().Get("materialized") == "true"
	configText, err := buildSwitch(a.provisionCfg(r, p, "switch"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "config": configText, "materialized": materialized,
	})
}

// handleProvisionerDownload: POST /api/provisioner/download — stessa config
// come file .txt. Sempre in audit: è materiale che esce dall'applicazione.
func (a *App) handleProvisionerDownload(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, err := buildSwitch(a.provisionCfg(r, p, "switch"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hostname := p.str("hostname", "switch")
	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf("Config day-0 generata (download) per '%s' da '%s'.",
		hostname, claims.Username))
	writeConfigDownload(w, configText, hostname+"-day0.txt")
}

// handleProvisionerPushSSH: POST /api/provisioner/push-ssh.
//
// La config applicata è quella materializzata, ma resta solo in memoria: nella
// risposta torna la versione con i placeholder (finding I-2).
func (a *App) handleProvisionerPushSSH(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, err := buildSwitch(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	host, creds := p.pushCreds("ssh_username", "ssh_password", "ssh_secret")
	if host == "" {
		writeErr(w, http.StatusBadRequest, "campo 'ssh_host' obbligatorio")
		return
	}

	res := provision.PushViaSSH(r.Context(), host, creds, configText, p.boolOr("save_after", true))
	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf(
		"Push SSH config day-0 su '%s' (hostname target: '%s') da '%s': %s.",
		host, p.str("hostname", ""), claims.Username, res.Status))

	a.respondPush(w, res, masked(p), buildSwitch)
}

// handleProvisionerPushSerial: POST /api/provisioner/push-serial.
func (a *App) handleProvisionerPushSerial(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, err := buildSwitch(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	comPort := p.str("com_port", "")
	if comPort == "" {
		writeErr(w, http.StatusBadRequest, "campo 'com_port' obbligatorio")
		return
	}

	res := provision.PushViaSerial(comPort, configText, p.intOr("baudrate", 9600))
	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf(
		"Push seriale (%s) config day-0 (hostname target: '%s') da '%s': %s.",
		comPort, p.str("hostname", ""), claims.Username, res.Status))

	a.respondPush(w, res, masked(p), buildSwitch)
}

// handleProvisionerSerialPorts: GET /api/provisioner/serial-ports.
func (a *App) handleProvisionerSerialPorts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ports": provision.ListSerialPorts()})
}

// respondPush scrive l'esito del push allegando la config MASCHERATA: quella
// materializzata è servita solo all'apparato e non deve tornare al client.
func (a *App) respondPush(w http.ResponseWriter, res provision.PushResult,
	maskedPayload provisionPayload, build func(provisionPayload) (string, error)) {

	out := map[string]any{"status": res.Status}
	if res.Output != "" {
		out["output"] = res.Output
	}
	if res.Message != "" {
		out["message"] = res.Message
	}
	if res.Method != "" {
		out["method"] = res.Method
	}
	if res.APIError != "" {
		out["api_error"] = res.APIError
	}
	if cfg, err := build(maskedPayload); err == nil {
		out["config"] = cfg
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- FortiGate ----

// handleFGTProvisionerGenerate: POST /api/provisioner/fgt/generate.
func (a *App) handleFGTProvisionerGenerate(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	materialized := r.URL.Query().Get("materialized") == "true"
	configText, err := buildFortiGate(a.provisionCfg(r, p, "FortiGate"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf("Config FortiGate day-0 generata per '%s' da '%s'.",
		p.str("hostname", ""), claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "config": configText, "materialized": materialized,
	})
}

// handleFGTProvisionerDownload: POST /api/provisioner/fgt/download.
func (a *App) handleFGTProvisionerDownload(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, err := buildFortiGate(a.provisionCfg(r, p, "FortiGate"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	hostname := p.str("hostname", "fortigate")
	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf("Config FortiGate day-0 (download) per '%s' da '%s'.",
		hostname, claims.Username))
	writeConfigDownload(w, configText, hostname+"-day0.txt")
}

// handleFGTProvisionerPushSSH: POST /api/provisioner/fgt/push-ssh.
//
// REST API per prima quando esiste un token per l'host, con ripiego SSH: è lo
// stesso schema dell'osservabilità. 'method' dice quale canale ha funzionato,
// 'api_error' perché il primo non è bastato.
func (a *App) handleFGTProvisionerPushSSH(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, err := buildFortiGate(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	host, creds := p.pushCreds("ssh_username", "ssh_password", "")
	if host == "" {
		writeErr(w, http.StatusBadRequest, "campo 'ssh_host' obbligatorio")
		return
	}

	var res provision.PushResult
	var apiErr string
	if c, err := a.fgtClient(host); err == nil {
		res = provision.PushFortiGateViaAPI(r.Context(), c, configText, "")
		if res.Status == "success" {
			res.Method = "api"
		} else {
			apiErr = res.Message
			res = provision.PushResult{}
		}
	}
	if res.Status == "" {
		res = provision.PushFortiGateViaSSH(r.Context(), host, creds, configText)
		res.Method = "ssh"
		res.APIError = apiErr
	}

	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf(
		"Push config FortiGate day-0 via %s su '%s' (hostname target: '%s') da '%s': %s.",
		res.Method, host, p.str("hostname", ""), claims.Username, res.Status))

	a.respondPush(w, res, masked(p), buildFortiGate)
}

// handleFGTProvisionerPushSerial: POST /api/provisioner/fgt/push-serial.
func (a *App) handleFGTProvisionerPushSerial(w http.ResponseWriter, r *http.Request) {
	p, err := decodeProvisionPayload(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	configText, err := buildFortiGate(p)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	comPort := p.str("com_port", "")
	if comPort == "" {
		writeErr(w, http.StatusBadRequest, "campo 'com_port' obbligatorio")
		return
	}

	res := provision.PushFortiGateViaSerial(comPort, configText,
		p.intOr("baudrate", 9600), p.str("console_user", "admin"), p.str("console_password", ""))

	claims := claimsFrom(r.Context())
	a.auditLog(fmt.Sprintf(
		"Push seriale (%s) config FortiGate day-0 (hostname target: '%s') da '%s': %s.",
		comPort, p.str("hostname", ""), claims.Username, res.Status))

	a.respondPush(w, res, masked(p), buildFortiGate)
}
