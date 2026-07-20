// Package api: handler HTTP per il FortiGate — gestione dei target REST
// (token, porta, verifica TLS) e osservabilità (stato, ARP, DHCP, policy,
// sessioni, log di traffico...). Porta di routers/fortigate_router.py.
package api

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/driver"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fortigate"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

// ---- helper interni ----

// fgtClient carica il target FortiGate salvato per questo IP e ne decifra il
// token, costruendo il client REST. Errore chiaro se il target non esiste,
// così i chiamanti che non hanno già verificato l'esistenza (fgtDevice)
// ottengono un messaggio comprensibile invece di un nil pointer.
func (a *App) fgtClient(ip string) (*fortigate.Client, error) {
	t, err := a.store.GetFortiGateTarget(ip)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, fmt.Errorf("nessun target FortiGate configurato per %s", ip)
	}
	token, err := a.vault.Decrypt(t.TokenEnc)
	if err != nil {
		return nil, err
	}
	return fortigate.New(t.IP, t.Port, token, t.VerifyTLS), nil
}

// fgtSSH costruisce il ripiego SSH per le funzioni di osservabilità del
// FortiGate: apre una sessione con le credenziali del device, esegue il
// comando e la chiude.
//
// NOTA: la regex promptRe di internal/collect non è ancora stata verificata
// contro i prompt di FortiOS (tipicamente "hostname (vdom) #"), quindi questo
// ripiego potrebbe non riconoscere correttamente il prompt su tutti gli
// apparati: va provato sul campo prima di considerarlo affidabile.
func (a *App) fgtSSH(d *store.Device) fortigate.SSHRunner {
	return func(ctx context.Context, command string) (string, error) {
		sess, err := collect.Dial(ctx, d.IP, a.resolveCreds(d))
		if err != nil {
			return "", err
		}
		defer sess.Close()
		return sess.Run(command), nil
	}
}

// fgtDevice risolve l'IP nel device di inventario (con lo scoping tenant di
// assertDeviceAllowed), verifica che il vendor sia un FortiGate e costruisce
// il client REST. In caso di esito negativo scrive già la risposta HTTP e
// ritorna ok=false: il chiamante deve solo fare return.
func (a *App) fgtDevice(w http.ResponseWriter, r *http.Request) (*store.Device, *fortigate.Client, bool) {
	ip := chi.URLParam(r, "ip")
	d, ok := a.assertDeviceAllowed(w, r, ip)
	if !ok {
		return nil, nil, false
	}
	if !driver.IsFortinet(d.Vendor) {
		writeErr(w, http.StatusBadRequest, "il dispositivo non è un FortiGate")
		return nil, nil, false
	}
	c, err := a.fgtClient(ip)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return nil, nil, false
	}
	return d, c, true
}

// fgtRespond scrive il risultato di una funzione di osservabilità (Result già
// nella busta {source, api_error?, data}), oppure 502 con il messaggio
// d'errore quando sia la REST che l'eventuale ripiego SSH hanno fallito.
func fgtRespond(w http.ResponseWriter, res fortigate.Result, err error) {
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---- gestione target (admin) ----

// handleFGTTokens: GET /api/fortigate/tokens — mappa ip -> {port, verify_tls}.
// Il token non compare mai nella risposta.
func (a *App) handleFGTTokens(w http.ResponseWriter, r *http.Request) {
	targets, err := a.store.ListFortiGateTargets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]map[string]any{}
	for _, t := range targets {
		out[t.IP] = map[string]any{"port": t.Port, "verify_tls": t.VerifyTLS}
	}
	writeJSON(w, http.StatusOK, out)
}

type fgtTokenReq struct {
	IP        string `json:"ip"`
	Token     string `json:"token"`
	Port      int    `json:"port"`
	VerifyTLS bool   `json:"verify_tls"`
	Name      string `json:"name"`
}

// handleFGTSetToken: POST /api/fortigate/token — crea/aggiorna un target, o lo
// elimina se il token è vuoto (comportamento della UI: cancellare il token
// nel form rimuove il target invece di salvarne uno senza credenziali).
func (a *App) handleFGTSetToken(w http.ResponseWriter, r *http.Request) {
	var req fgtTokenReq
	if err := decodeJSON(r, &req); err != nil || req.IP == "" {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	claims := claimsFrom(r.Context())

	if req.Token == "" {
		if err := a.store.DeleteFortiGateTarget(req.IP); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		a.auditLog("Target FortiGate " + req.IP + " rimosso da '" + claims.Username + "'.")
		writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
		return
	}

	enc, err := a.vault.Encrypt(req.Token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	t := &store.FortiGateTarget{
		IP: req.IP, Name: req.Name, Port: req.Port, VerifyTLS: req.VerifyTLS, TokenEnc: enc,
	}
	if err := a.store.UpsertFortiGateTarget(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Token FortiGate impostato per " + req.IP + " da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// handleFGTTargets: GET /api/fortigate/targets — elenco completo. I campi
// JSON di store.FortiGateTarget escludono già il token (TokenEnc: json:"-").
func (a *App) handleFGTTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := a.store.ListFortiGateTargets()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, targets)
}

type fgtActiveReq struct {
	IP string `json:"ip"`
}

// handleFGTSetActiveTarget: POST /api/fortigate/targets/active.
func (a *App) handleFGTSetActiveTarget(w http.ResponseWriter, r *http.Request) {
	var req fgtActiveReq
	if err := decodeJSON(r, &req); err != nil || req.IP == "" {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	t, err := a.store.GetFortiGateTarget(req.IP)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if t == nil {
		writeErr(w, http.StatusNotFound, "target non trovato")
		return
	}
	if err := a.store.SetActiveFortiGateTarget(req.IP); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Target FortiGate attivo impostato a " + req.IP + " da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// handleFGTTestTarget: POST /api/fortigate/targets/{ip}/test — verifica di
// raggiungibilità. TestConnection non ritorna mai un errore Go: l'esito
// negativo fa parte del corpo della risposta (ok:false, error:"...").
func (a *App) handleFGTTestTarget(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	t, err := a.store.GetFortiGateTarget(ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if t == nil {
		writeErr(w, http.StatusNotFound, "target non trovato")
		return
	}
	token, err := a.vault.Decrypt(t.TokenEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	c := fortigate.New(t.IP, t.Port, token, t.VerifyTLS)
	writeJSON(w, http.StatusOK, c.TestConnection(r.Context()))
}

type fgtUpdateReq struct {
	Name      *string `json:"name"`
	Port      *int    `json:"port"`
	VerifyTLS *bool   `json:"verify_tls"`
	Token     *string `json:"token"`
}

// handleFGTUpdateTarget: PUT /api/fortigate/targets/{ip} — aggiornamento
// parziale: i campi assenti nel payload restano invariati. Il token si
// aggiorna solo se presente e non vuoto; altrimenti UpsertFortiGateTarget
// conserva quello già memorizzato (TokenEnc="").
func (a *App) handleFGTUpdateTarget(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	t, err := a.store.GetFortiGateTarget(ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if t == nil {
		writeErr(w, http.StatusNotFound, "target non trovato")
		return
	}
	var req fgtUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Name != nil {
		t.Name = *req.Name
	}
	if req.Port != nil {
		t.Port = *req.Port
	}
	if req.VerifyTLS != nil {
		t.VerifyTLS = *req.VerifyTLS
	}
	t.TokenEnc = "" // invariato di default: UpsertFortiGateTarget conserva quello esistente
	if req.Token != nil && *req.Token != "" {
		enc, err := a.vault.Encrypt(*req.Token)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		t.TokenEnc = enc
	}
	if err := a.store.UpsertFortiGateTarget(t); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Target FortiGate " + ip + " aggiornato da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// ---- osservabilità (auth: qualunque utente, salvo dove indicato) ----

func (a *App) handleFGTStatus(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.SystemStatus(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTInterfaces(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.Interfaces(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTARP(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.ARPTable(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTDHCPLeases(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.DHCPLeases(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTDeviceInventory(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.DeviceInventory(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTPolicies(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.FirewallPolicies(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTPolicyStats(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.PolicyStats(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTRoutes(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.Routes(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTWifiClients(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.WifiClients(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

func (a *App) handleFGTManagedAPs(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.ManagedAPs(r.Context(), a.fgtSSH(d))
	fgtRespond(w, res, err)
}

// handleFGTFirewallAddresses e i due handler seguenti sono solo REST: nessun
// ripiego SSH, quindi il device non serve oltre alla verifica di fgtDevice.
func (a *App) handleFGTFirewallAddresses(w http.ResponseWriter, r *http.Request) {
	_, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.FirewallAddresses(r.Context())
	fgtRespond(w, res, err)
}

func (a *App) handleFGTPolicyObjects(w http.ResponseWriter, r *http.Request) {
	_, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.PolicyObjects(r.Context())
	fgtRespond(w, res, err)
}

func (a *App) handleFGTCustomServices(w http.ResponseWriter, r *http.Request) {
	_, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.CustomServices(r.Context())
	fgtRespond(w, res, err)
}

type fgtPolicyLookupReq struct {
	SrcIP    string `json:"src_ip"`
	Dest     string `json:"dest"`
	Protocol string `json:"protocol"`
	DestPort int    `json:"dest_port"`
	SrcIntf  string `json:"srcintf"`
}

func (a *App) handleFGTPolicyLookup(w http.ResponseWriter, r *http.Request) {
	_, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	var req fgtPolicyLookupReq
	_ = decodeJSON(r, &req)
	if req.Protocol == "" {
		req.Protocol = "TCP"
	}
	if req.DestPort == 0 {
		req.DestPort = 443
	}
	res, err := c.PolicyLookup(r.Context(), req.SrcIP, req.Dest, req.Protocol, req.DestPort, req.SrcIntf)
	fgtRespond(w, res, err)
}

type fgtSessionsReq struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
	Count   int    `json:"count"`
}

func (a *App) handleFGTSessions(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	var req fgtSessionsReq
	_ = decodeJSON(r, &req)
	if req.Count == 0 {
		req.Count = 100
	}
	res, err := c.Sessions(r.Context(), req.SrcIP, req.DstIP, req.DstPort, req.Count, a.fgtSSH(d))
	fgtRespond(w, res, err)
}

type fgtLogsReq struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Action    string `json:"action"`
	Count     int    `json:"count"`
	LogDevice string `json:"log_device"`
}

// handleFGTLogs: POST /api/fortigate/{ip}/logs — la Result più il campo
// log_device, che riporta quale dei due (disk/memory) ha effettivamente
// risposto: TrafficLogs prova prima quello richiesto e poi l'altro.
func (a *App) handleFGTLogs(w http.ResponseWriter, r *http.Request) {
	_, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	var req fgtLogsReq
	_ = decodeJSON(r, &req)
	if req.Count == 0 {
		req.Count = 100
	}
	if req.LogDevice == "" {
		req.LogDevice = "disk"
	}
	res, dev, err := c.TrafficLogs(r.Context(), req.SrcIP, req.DstIP, req.Action, req.Count, req.LogDevice)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out := map[string]any{"source": res.Source, "data": res.Data, "log_device": dev}
	if res.APIError != "" {
		out["api_error"] = res.APIError
	}
	writeJSON(w, http.StatusOK, out)
}

// handleFGTFullConfig: GET /api/fortigate/{ip}/full-config — richiede
// 'operator' (contiene segreti) e va sempre registrato in audit.
func (a *App) handleFGTFullConfig(w http.ResponseWriter, r *http.Request) {
	d, c, ok := a.fgtDevice(w, r)
	if !ok {
		return
	}
	res, err := c.FullConfig(r.Context(), a.fgtSSH(d))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	claims := claimsFrom(r.Context())
	a.auditLog("Backup configurazione FortiGate " + d.IP + " scaricato da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, res)
}
