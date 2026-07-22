package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/mcp"
)

const (
	mcpPreviewEnabledKey = "mcp_preview_enabled"
	mcpClientServersKey  = "mcp_client_servers"
)

type mcpClientServerEntry struct {
	Name    string `json:"name"`
	URL     string `json:"url"`
	AuthEnc string `json:"auth_enc,omitempty"`
}

type mcpClientPreviewReq struct {
	Enabled bool `json:"enabled"`
}

type mcpClientServerReq struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	AuthToken string `json:"auth_token,omitempty"`
}

type mcpClientCallReq struct {
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

func (a *App) isMCPPreviewEnabled() bool {
	val := a.store.GetSetting(mcpPreviewEnabledKey, "false")
	return val == "true"
}

func (a *App) loadMCPClientServers() []mcpClientServerEntry {
	raw := a.store.GetSetting(mcpClientServersKey, "")
	if raw == "" {
		return []mcpClientServerEntry{}
	}
	var list []mcpClientServerEntry
	_ = json.Unmarshal([]byte(raw), &list)
	return list
}

func (a *App) saveMCPClientServers(list []mcpClientServerEntry) error {
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return a.store.SetSetting(mcpClientServersKey, string(b))
}

func (a *App) findMCPClientServer(name string) *mcpClientServerEntry {
	for _, s := range a.loadMCPClientServers() {
		if s.Name == name {
			return &s
		}
	}
	return nil
}

func publicMCPClientServer(s mcpClientServerEntry) map[string]any {
	return map[string]any{
		"name":     s.Name,
		"url":      s.URL,
		"has_auth": s.AuthEnc != "",
	}
}

func (a *App) handleGetMCPClientSettings(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	servers := a.loadMCPClientServers()
	publicList := make([]map[string]any, len(servers))
	for i, s := range servers {
		publicList[i] = publicMCPClientServer(s)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"preview_enabled": a.isMCPPreviewEnabled(),
		"servers":         publicList,
	})
}

func (a *App) handleSetMCPClientPreview(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	var req mcpClientPreviewReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	val := "false"
	if req.Enabled {
		val = "true"
	}
	if err := a.store.SetSetting(mcpPreviewEnabledKey, val); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	statusStr := "disabilitato"
	if req.Enabled {
		statusStr = "abilitato"
	}
	a.auditLog("MCP Client (preview) " + statusStr + " da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "success",
		"preview_enabled": req.Enabled,
	})
}

func (a *App) handleListMCPClientServers(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	servers := a.loadMCPClientServers()
	publicList := make([]map[string]any, len(servers))
	for i, s := range servers {
		publicList[i] = publicMCPClientServer(s)
	}

	writeJSON(w, http.StatusOK, map[string]any{"servers": publicList})
}

func (a *App) handleUpsertMCPClientServer(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	var req mcpClientServerReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	name := strings.TrimSpace(req.Name)
	url := strings.TrimSpace(req.URL)
	if name == "" || url == "" {
		writeErr(w, http.StatusBadRequest, "Nome e URL sono obbligatori.")
		return
	}

	lowerURL := strings.ToLower(url)
	if !strings.HasPrefix(lowerURL, "http://") && !strings.HasPrefix(lowerURL, "https://") {
		writeErr(w, http.StatusBadRequest, "L'URL deve iniziare con http:// o https://.")
		return
	}

	servers := a.loadMCPClientServers()
	existing := a.findMCPClientServer(name)

	authEnc := ""
	if existing != nil {
		authEnc = existing.AuthEnc
	}

	if req.AuthToken != "" && a.vault != nil {
		enc, err := a.vault.Encrypt(req.AuthToken)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "errore cifratura token")
			return
		}
		authEnc = enc
	}

	entry := mcpClientServerEntry{
		Name:    name,
		URL:     url,
		AuthEnc: authEnc,
	}

	var updated []mcpClientServerEntry
	for _, s := range servers {
		if s.Name != name {
			updated = append(updated, s)
		}
	}
	updated = append(updated, entry)

	if err := a.saveMCPClientServers(updated); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog("Server MCP client '" + name + "' salvato da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success",
		"server": publicMCPClientServer(entry),
	})
}

func (a *App) handleDeleteMCPClientServer(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	name := r.PathValue("name")
	if name == "" {
		writeErr(w, http.StatusBadRequest, "Nome server mancante")
		return
	}

	servers := a.loadMCPClientServers()
	found := false
	var remaining []mcpClientServerEntry
	for _, s := range servers {
		if s.Name == name {
			found = true
		} else {
			remaining = append(remaining, s)
		}
	}

	if !found {
		writeErr(w, http.StatusNotFound, "Server non trovato.")
		return
	}

	if err := a.saveMCPClientServers(remaining); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog("Server MCP client '" + name + "' eliminato da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

func (a *App) decryptServerAuth(s *mcpClientServerEntry) string {
	if s == nil || s.AuthEnc == "" || a.vault == nil {
		return ""
	}
	dec, err := a.vault.Decrypt(s.AuthEnc)
	if err != nil {
		return ""
	}
	return dec
}

func (a *App) handleGetMCPClientTools(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	if !a.isMCPPreviewEnabled() {
		writeErr(w, http.StatusForbidden, "MCP Client (preview) non abilitato.")
		return
	}

	name := r.PathValue("name")
	server := a.findMCPClientServer(name)
	if server == nil {
		writeErr(w, http.StatusNotFound, "Server non trovato.")
		return
	}

	authToken := a.decryptServerAuth(server)
	client := mcp.NewExternalClient(server.URL, authToken)
	tools, err := client.ListTools()
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"tools": tools})
}

func (a *App) handleCallMCPClientTool(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if !roleAtLeast(claims.Role, "admin") {
		writeErr(w, http.StatusForbidden, "Permessi insufficienti")
		return
	}

	if !a.isMCPPreviewEnabled() {
		writeErr(w, http.StatusForbidden, "MCP Client (preview) non abilitato.")
		return
	}

	name := r.PathValue("name")
	server := a.findMCPClientServer(name)
	if server == nil {
		writeErr(w, http.StatusNotFound, "Server non trovato.")
		return
	}

	var req mcpClientCallReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	if strings.TrimSpace(req.Tool) == "" {
		writeErr(w, http.StatusBadRequest, "Nome del tool obbligatorio.")
		return
	}

	authToken := a.decryptServerAuth(server)
	client := mcp.NewExternalClient(server.URL, authToken)
	res, err := client.CallTool(req.Tool, req.Arguments)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}

	a.auditLog("Tool MCP client '" + req.Tool + "' invocato su '" + name + "' da '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"result": res})
}
