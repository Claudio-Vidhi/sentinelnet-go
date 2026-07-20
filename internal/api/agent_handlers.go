package api

import (
	"net/http"
	"strconv"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

// Rotte riceventi degli agenti di sede.
//
// L'autenticazione NON passa dal JWT utente: un agente è un processo, non una
// persona, e si presenta con il token della propria sede negli header
// X-Site-Token (+ opzionale X-Site-Id).
//
// Il contratto di trasporto è vincolante: gli agenti Python già installati sul
// campo continuano a parlare con questo server, quindi header, forme JSON e
// semantica del claim dei job non possono cambiare (§5.C del piano). Per lo
// stesso motivo site_agent.py non è portato: si portano solo le rotte.

// agentSite autentica l'agente e ritorna la sua sede. In caso di esito
// negativo scrive già la risposta e ritorna nil.
func (a *App) agentSite(w http.ResponseWriter, r *http.Request) *store.Site {
	token := r.Header.Get("X-Site-Token")
	claimedID := r.Header.Get("X-Site-Id")

	siteID, err := a.store.AuthenticateSite(token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil
	}
	// Un X-Site-Id che non corrisponde al token è un errore di configurazione
	// dell'agente, o un tentativo di spacciarsi per un'altra sede: in entrambi
	// i casi non si prosegue.
	if siteID == "" || (claimedID != "" && claimedID != siteID) {
		writeErr(w, http.StatusUnauthorized, "Token di sede non valido.")
		return nil
	}

	if err := a.store.TouchSiteLastSeen(siteID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return nil
	}
	site, err := a.store.GetSite(siteID)
	if err != nil || site == nil {
		writeErr(w, http.StatusUnauthorized, "Token di sede non valido.")
		return nil
	}
	return site
}

// handleAgentHeartbeat: POST /api/agent/heartbeat.
func (a *App) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	site := a.agentSite(w, r)
	if site == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "site_id": site.ID, "name": site.Name, "subnets": site.Subnets,
	})
}

type agentDevice struct {
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`
	Hostname string `json:"hostname"`
}

type agentInventoryReq struct {
	Devices []agentDevice `json:"devices"`
}

// handleAgentInventory: POST /api/agent/inventory — l'agente spinge il proprio
// inventario locale, che viene rispecchiato sul centrale e taggato con la sede.
//
// Le credenziali NON sono replicate: i comandi passano dal relay ed è l'agente
// a eseguirli in locale, quindi il centrale non ha motivo di conoscerle.
func (a *App) handleAgentInventory(w http.ResponseWriter, r *http.Request) {
	site := a.agentSite(w, r)
	if site == nil {
		return
	}
	var req agentInventoryReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	// Tenant già assegnati: un push non deve declassare a 'Generale' un
	// dispositivo che un operatore ha attribuito a un tenant preciso.
	existing := map[string]string{}
	if devices, err := a.store.ListDevices(); err == nil {
		for _, d := range devices {
			existing[d.IP] = d.Tenant
		}
	}

	n := 0
	for _, d := range req.Devices {
		if !reIPv4.MatchString(d.IP) {
			continue
		}
		tenant := existing[d.IP]
		if tenant == "" {
			tenant = "Generale"
		}
		vendor := d.Vendor
		if vendor == "" {
			vendor = "cisco"
		}
		if err := a.store.UpsertDevice(&store.Device{
			IP: d.IP, Vendor: vendor, Profile: "custom", Tenant: tenant,
			Hostname: d.Hostname, Site: site.ID,
		}); err != nil {
			continue
		}
		n++
	}

	a.auditLog("Agente sede '" + site.ID + "': inventario aggiornato (" +
		strconv.Itoa(n) + " dispositivi).")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "updated": n})
}

type agentMacCollection struct {
	SwitchIP   string              `json:"switch_ip"`
	SwitchName string              `json:"switch_name"`
	Rows       []map[string]string `json:"rows"`
}

type agentMacReq struct {
	Collections []agentMacCollection `json:"collections"`
}

// handleAgentMac: POST /api/agent/mac — l'agente spinge le MAC-table raccolte
// localmente, storicizzate con attribuzione alla sede.
//
// Il tenant è quello del device in inventario e non l'id della sede: lo
// scoping degli utenti filtra per tenant, ed è la stessa scelta della raccolta
// centrale.
func (a *App) handleAgentMac(w http.ResponseWriter, r *http.Request) {
	site := a.agentSite(w, r)
	if site == nil {
		return
	}
	var req agentMacReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	tenants := map[string]string{}
	if devices, err := a.store.ListDevices(); err == nil {
		for _, d := range devices {
			tenants[d.IP] = d.Tenant
		}
	}

	total := 0
	for _, col := range req.Collections {
		tenant := tenants[col.SwitchIP]
		if tenant == "" {
			tenant = "Generale"
		}
		for _, row := range col.Rows {
			mac := row["mac"]
			if mac == "" {
				continue
			}
			if err := a.store.UpsertSighting(&store.MacSighting{
				Mac:         mac,
				Vlan:        row["vlan"],
				Interface:   row["interface"],
				PortChannel: row["port_channel"],
				SwitchIP:    col.SwitchIP,
				SwitchName:  col.SwitchName,
				Tenant:      tenant,
				Site:        site.ID,
			}); err != nil {
				continue
			}
			total++
		}
	}

	a.auditLog("Agente sede '" + site.ID + "': " + strconv.Itoa(len(req.Collections)) +
		" MAC-table ricevute (" + strconv.Itoa(total) + " avvistamenti).")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "recorded": total})
}

// handleAgentPollJobs: GET /api/agent/jobs — l'agente preleva i job pendenti,
// che restano marcati 'running'.
func (a *App) handleAgentPollJobs(w http.ResponseWriter, r *http.Request) {
	site := a.agentSite(w, r)
	if site == nil {
		return
	}
	jobs, err := a.store.ClaimPendingJobs(site.ID, 20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

type agentJobResultReq struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// handleAgentJobResult: POST /api/agent/jobs/{job_id}/result.
//
// 404 anche quando il job esiste ma è di un'altra sede: confermarne
// l'esistenza direbbe a un agente qualcosa sulle sedi che non gli competono.
func (a *App) handleAgentJobResult(w http.ResponseWriter, r *http.Request) {
	site := a.agentSite(w, r)
	if site == nil {
		return
	}
	var req agentJobResultReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Status == "" {
		req.Status = "done"
	}
	ok, err := a.store.CompleteJob(chi.URLParam(r, "job_id"), site.ID, req.Status, req.Result)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "Job non trovato per questa sede.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}
