package api

import (
	"net/http"
	"strings"
)

func (a *App) handleListGroups(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	tenants, err := a.store.ListTenants()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]map[string]string{}
	for _, t := range tenants {
		if scoped != nil && !canSeeTenant(scoped, t.Name) {
			continue
		}
		out[t.Name] = map[string]string{"description": t.Description}
	}
	writeJSON(w, http.StatusOK, out)
}

type groupReq struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (a *App) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req groupReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeErr(w, http.StatusBadRequest, "nome tenant obbligatorio")
		return
	}
	if ok, _ := a.store.TenantExists(req.Name); ok {
		writeErr(w, http.StatusConflict, "tenant già esistente")
		return
	}
	if req.Description == "" {
		req.Description = "Sede secondaria " + req.Name
	}
	if err := a.store.CreateTenant(req.Name, req.Description); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type renameGroupReq struct {
	OldName string `json:"old_name"`
	NewName string `json:"new_name"`
}

func (a *App) handleRenameGroup(w http.ResponseWriter, r *http.Request) {
	var req renameGroupReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	req.NewName = strings.TrimSpace(req.NewName)
	if req.OldName == "Generale" {
		writeErr(w, http.StatusBadRequest, "il tenant Generale non è rinominabile")
		return
	}
	if req.NewName == "" {
		writeErr(w, http.StatusBadRequest, "nuovo nome obbligatorio")
		return
	}
	if ok, _ := a.store.TenantExists(req.OldName); !ok {
		writeErr(w, http.StatusNotFound, "tenant inesistente")
		return
	}
	if ok, _ := a.store.TenantExists(req.NewName); ok {
		writeErr(w, http.StatusConflict, "esiste già un tenant con questo nome")
		return
	}
	if err := a.store.RenameTenant(req.OldName, req.NewName); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type deleteGroupReq struct {
	Name string `json:"name"`
}

func (a *App) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	var req deleteGroupReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Name == "Generale" {
		writeErr(w, http.StatusBadRequest, "il tenant Generale è protetto")
		return
	}
	if err := a.store.DeleteTenant(req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Vendors ----

func (a *App) handleListVendors(w http.ResponseWriter, _ *http.Request) {
	vendors, err := a.store.ListVendors()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, vendors)
}

type vendorReq struct {
	Name     string `json:"name"`
	EUVDTerm string `json:"euvd_term"`
	Driver   string `json:"driver"`
}

func (a *App) handleAddVendor(w http.ResponseWriter, r *http.Request) {
	var req vendorReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	req.Name = strings.ToLower(strings.TrimSpace(req.Name))
	if req.Name == "" || strings.TrimSpace(req.EUVDTerm) == "" {
		writeErr(w, http.StatusBadRequest, "nome e EUVD term obbligatori")
		return
	}
	if err := a.store.UpsertVendor(req.Name, strings.TrimSpace(req.EUVDTerm), strings.TrimSpace(req.Driver)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type nameReq struct {
	Name string `json:"name"`
}

func (a *App) handleDeleteVendor(w http.ResponseWriter, r *http.Request) {
	var req nameReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Name == "cisco" || req.Name == "hpe" {
		writeErr(w, http.StatusBadRequest, "vendor di sistema non eliminabile")
		return
	}
	if err := a.store.DeleteVendor(req.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Models ----

func (a *App) handleListModels(w http.ResponseWriter, _ *http.Request) {
	models, err := a.store.ListModels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, models)
}

type modelReq struct {
	Vendor string `json:"vendor"`
	Model  string `json:"model"`
}

func (a *App) handleAddModel(w http.ResponseWriter, r *http.Request) {
	var req modelReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	req.Vendor = strings.ToLower(strings.TrimSpace(req.Vendor))
	req.Model = strings.TrimSpace(req.Model)
	if req.Vendor == "" || req.Model == "" {
		writeErr(w, http.StatusBadRequest, "vendor e model obbligatori")
		return
	}
	if err := a.store.AddModel(req.Vendor, req.Model); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleDeleteModel(w http.ResponseWriter, r *http.Request) {
	var req modelReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := a.store.DeleteModel(strings.ToLower(req.Vendor), req.Model); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
