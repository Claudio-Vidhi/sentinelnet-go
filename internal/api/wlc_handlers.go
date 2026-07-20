// Package api: handler HTTP per i controller WLC Cisco (AireOS / Catalyst
// 9800) — osservabilità via SSH. Porta di routers/wlc.py.
package api

import (
	"context"
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/wlc"
	"github.com/go-chi/chi/v5"
)

// ---- helper interni ----

// wlcRunner costruisce il trasporto SSH per le funzioni di osservabilità del
// WLC e la funzione che ne rilascia la sessione, che il chiamante deve
// invocare (defer).
//
// La sessione è aperta al primo comando e poi riusata: una diagnosi ne esegue
// quattro, e riaprirla ogni volta significherebbe quattro handshake SSH verso
// lo stesso controller. Il Python riapre la connessione a ogni comando; qui
// non è una differenza di comportamento, solo di costo.
//
// La paginazione è disabilitata una volta sola, sulla sessione riusata, e con
// il comando della piattaforma: AireOS non capisce "terminal length 0" (che
// collect.Dial invia già di suo) e senza "config paging disable" un output
// lungo si ferma al primo "--More--".
//
// Non è utilizzabile in concorrenza: i comandi di una richiesta sono
// sequenziali, e la sessione SSH sottostante è un singolo canale.
func (a *App) wlcRunner(d *store.Device) (wlc.Runner, func()) {
	var sess *collect.Session
	paged := false

	run := func(ctx context.Context, p wlc.Platform, command string) (string, error) {
		if sess == nil {
			// Un fallimento non viene memorizzato: una sezione che non si
			// collega non deve impedire alle successive di riprovare.
			s, err := collect.Dial(ctx, d.IP, a.resolveCreds(d))
			if err != nil {
				return "", err
			}
			sess = s
		}
		if !paged {
			sess.Run(p.PagingCommand())
			paged = true
		}
		return sess.Run(command), nil
	}

	return run, func() {
		if sess != nil {
			sess.Close()
		}
	}
}

// wlcDevice risolve l'IP nel device di inventario (con lo scoping tenant di
// assertDeviceAllowed) e verifica che il vendor sia un controller wireless
// Cisco gestibile. In caso di esito negativo scrive già la risposta HTTP e
// ritorna ok=false: il chiamante deve solo fare return.
func (a *App) wlcDevice(w http.ResponseWriter, r *http.Request) (*store.Device, bool) {
	ip := chi.URLParam(r, "ip")
	d, ok := a.assertDeviceAllowed(w, r, ip)
	if !ok {
		return nil, false
	}
	if !wlc.IsWLCVendor(d.Vendor) {
		writeErr(w, http.StatusBadRequest, "il dispositivo non è un WLC Cisco")
		return nil, false
	}
	return d, true
}

// wlcRespond scrive il risultato di un servizio WLC, oppure 502 col messaggio
// d'errore quando la connessione/il comando SSH è fallito: un guasto di
// trasporto verso l'apparato, da distinguere da un errore applicativo.
func wlcRespond(w http.ResponseWriter, res wlc.Result, err error) {
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// wlcQuery esegue il servizio richiesto sul device risolto da wlcDevice e
// scrive la risposta.
func (a *App) wlcQuery(w http.ResponseWriter, r *http.Request, service, mac string) {
	d, ok := a.wlcDevice(w, r)
	if !ok {
		return
	}
	run, closeSession := a.wlcRunner(d)
	defer closeSession()

	res, err := wlc.Query(r.Context(), run, d.Vendor, service, mac)
	wlcRespond(w, res, err)
}

// ---- osservabilità (auth: qualunque utente) ----

func (a *App) handleWLCStatus(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "status", "")
}

func (a *App) handleWLCAPSummary(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "ap_summary", "")
}

func (a *App) handleWLCClientSummary(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "client_summary", "")
}

func (a *App) handleWLCClientDetail(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "client_detail", chi.URLParam(r, "mac"))
}

func (a *App) handleWLCWLANSummary(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "wlan_summary", "")
}

func (a *App) handleWLCRogueAPs(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "rogue_aps", "")
}

func (a *App) handleWLCInterfaces(w http.ResponseWriter, r *http.Request) {
	a.wlcQuery(w, r, "interfaces", "")
}

// handleWLCDiagnoseClient: GET /api/wlc/{ip}/diagnose-client/{mac} — diagnosi
// aggregata di un client wireless (dettaglio client + AP + WLAN + rogue AP).
//
// Non usa wlcRespond: come per il FortiGate, la diagnosi non fallisce mai in
// blocco perché ogni sezione porta con sé il proprio errore. Un 502 qui
// vorrebbe dire "non so niente", mentre una diagnosi parziale è comunque
// quello che serve all'operatore.
func (a *App) handleWLCDiagnoseClient(w http.ResponseWriter, r *http.Request) {
	d, ok := a.wlcDevice(w, r)
	if !ok {
		return
	}
	mac := chi.URLParam(r, "mac")

	claims := claimsFrom(r.Context())
	a.auditLog("Diagnosi client WiFi '" + mac + "' su WLC " + d.IP + " da '" + claims.Username + "'.")

	run, closeSession := a.wlcRunner(d)
	defer closeSession()

	res := wlc.DiagnoseWifiClient(r.Context(), run, d.IP, d.Vendor, mac)
	writeJSON(w, http.StatusOK, res)
}
