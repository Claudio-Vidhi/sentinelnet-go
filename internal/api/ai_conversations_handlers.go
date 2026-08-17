package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/go-chi/chi/v5"
)

// GET /api/ai/conversations
func (a *App) handleListAIConversations(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	list, err := a.store.ListAIConversations(claims.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"conversations": list})
}

type createAIConvReq struct {
	Title    string `json:"title"`
	Messages []any  `json:"messages"`
}

// POST /api/ai/conversations
func (a *App) handleCreateAIConversation(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req createAIConvReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	conv, err := a.store.CreateAIConversation(req.Title, req.Messages, claims.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, conv)
}

// GET /api/ai/conversations/{id}
func (a *App) handleGetAIConversation(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	conv, err := a.store.GetAIConversation(id, claims.Username)
	if err != nil || conv == nil {
		writeErr(w, http.StatusNotFound, "Conversazione non trovata.")
		return
	}
	writeJSON(w, http.StatusOK, conv)
}

type updateAIConvReq struct {
	Title    string `json:"title"`
	Messages []any  `json:"messages"`
}

// PUT /api/ai/conversations/{id}
func (a *App) handleUpdateAIConversation(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	var req updateAIConvReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	conv, err := a.store.UpdateAIConversation(id, req.Title, req.Messages, claims.Username)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, conv)
}

// DELETE /api/ai/conversations/{id}
func (a *App) handleDeleteAIConversation(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid ID.")
		return
	}

	_ = a.store.DeleteAIConversation(id, claims.Username)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})
}

// --- SNMP Defaults ---

// GET /api/settings/snmp-defaults
func (a *App) handleGetSNMPDefaults(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	tenants, err := a.store.GetSNMPTenantDefaults()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var filtered []string
	for _, t := range tenants {
		if allowedTenants == nil || containsStr(allowedTenants, t) {
			filtered = append(filtered, t)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": filtered})
}

type setSNMPDefaultReq struct {
	Tenant    string `json:"tenant"`
	Community string `json:"community"`
}

// POST /api/settings/snmp-defaults
func (a *App) handleSetSNMPDefaults(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	var req setSNMPDefaultReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	if allowedTenants != nil && !containsStr(allowedTenants, req.Tenant) {
		writeErr(w, http.StatusForbidden, fmt.Sprintf("Tenant '%s' non consentito per il tuo profilo.", req.Tenant))
		return
	}

	if err := a.store.SetSNMPTenantDefault(req.Tenant, req.Community); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	action := "impostata"
	if req.Community == "" {
		action = "rimossa"
	}
	a.auditLog(fmt.Sprintf("Community SNMP predefinita tenant '%s' %s da '%s'.", req.Tenant, action, claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

// --- UI Variant Settings ---

// GET /api/settings/ui-variant
func (a *App) handleGetUIVariant(w http.ResponseWriter, _ *http.Request) {
	variant := a.store.GetSetting("ui_variant", "default")
	writeJSON(w, http.StatusOK, map[string]any{"variant": variant})
}

type setUIVariantReq struct {
	Variant string `json:"variant"`
}

// POST /api/settings/ui-variant
func (a *App) handleSetUIVariant(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req setUIVariantReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	if err := a.store.SetSetting("ui_variant", req.Variant); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog(fmt.Sprintf("UI Variant impostata a '%s' da '%s'.", req.Variant, claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "variant": req.Variant})
}

// --- Identity Bulk Assignment ---

type assignIdentityReq struct {
	IPs []string `json:"ips"`
}

// POST /api/identities/{id}/assign
func (a *App) handleAssignIdentity(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)
	id := chi.URLParam(r, "id")

	var req assignIdentityReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	profileTarget := fmt.Sprintf("identity:%s", id)
	assigned := 0

	for _, ip := range req.IPs {
		dev, err := a.store.GetDevice(ip)
		if err != nil || dev == nil {
			continue
		}
		if allowedTenants != nil && !containsStr(allowedTenants, dev.Tenant) {
			continue
		}
		dev.Profile = profileTarget
		if err := a.store.UpsertDevice(dev); err == nil {
			assigned++
		}
	}

	a.auditLog(fmt.Sprintf("Identita '%s' assegnata a %d dispositivi da '%s'.", id, assigned, claims.Username))
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "assigned_count": assigned})
}

// --- Global Search ---

type searchResultItem struct {
	Type        string `json:"type"` // "device", "endpoint", "arp", "tenant"
	Title       string `json:"title"`
	Subtitle    string `json:"subtitle"`
	Identifier  string `json:"identifier"`
	Tenant      string `json:"tenant"`
}

// GET /api/search
func (a *App) handleGlobalSearch(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusOK, map[string]any{"query": q, "results": []any{}})
		return
	}
	qLower := strings.ToLower(q)

	var results []searchResultItem

	// 1. Search Devices
	devs, err := a.store.ListDevices()
	if err == nil {
		for _, d := range devs {
			if allowedTenants != nil && !containsStr(allowedTenants, d.Tenant) {
				continue
			}
			if strings.Contains(strings.ToLower(d.IP), qLower) || strings.Contains(strings.ToLower(d.Hostname), qLower) || strings.Contains(strings.ToLower(d.Vendor), qLower) {
				name := d.Hostname
				if name == "" {
					name = d.IP
				}
				results = append(results, searchResultItem{
					Type:       "device",
					Title:      name,
					Subtitle:   fmt.Sprintf("%s (%s)", d.IP, d.Vendor),
					Identifier: d.IP,
					Tenant:     d.Tenant,
				})
			}
		}
	}

	// 2. Search Endpoints & ARP
	epRes, err := a.store.EndpointInventory(store.EndpointInventoryOptions{
		Tenants: allowedTenants,
		Query:   q,
		Limit:   20,
	})
	if err == nil && epRes != nil {
		for _, ep := range epRes.Results {
			sub := ep.SwitchName
			if ep.Interface != "" {
				sub += " : " + ep.Interface
			}
			if len(ep.IPs) > 0 {
				sub += " (" + strings.Join(ep.IPs, ", ") + ")"
			}
			results = append(results, searchResultItem{
				Type:       "endpoint",
				Title:      ep.MAC,
				Subtitle:   sub,
				Identifier: ep.MAC,
				Tenant:     ep.Tenant,
			})
		}
	}

	if len(results) > 50 {
		results = results[:50]
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"query":   q,
		"total":   len(results),
		"results": results,
	})
}
