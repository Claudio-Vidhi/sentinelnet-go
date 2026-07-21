package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/mcp"
)

const mcpDisabledKey = "mcp_disabled_tools"

var mcpDefaultDisabled = []string{"get_anomalies", "get_top_talkers"}

// knownTool indica se name è un tool MCP noto.
func knownTool(name string) bool {
	for _, t := range mcp.Tools {
		if t.Name == name {
			return true
		}
	}
	return false
}

// mcpDisabledTools legge il set salvato (o il default se assente), filtrando i
// tool non più esistenti — equivalente a _mcp_disabled_tools() del Python.
func (a *App) mcpDisabledTools() []string {
	raw := a.store.GetSetting(mcpDisabledKey, "")
	if raw == "" {
		out := []string{}
		for _, n := range mcpDefaultDisabled {
			if knownTool(n) {
				out = append(out, n)
			}
		}
		sort.Strings(out)
		return out
	}
	var saved []string
	json.Unmarshal([]byte(raw), &saved)
	out := []string{}
	for _, n := range saved {
		if knownTool(n) {
			out = append(out, n)
		}
	}
	return out
}

func (a *App) handleGetMCPSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tools":          mcp.Catalog(),
		"disabled_tools": a.mcpDisabledTools(),
	})
}

func (a *App) handleSetMCPSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DisabledTools []string `json:"disabled_tools"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	var unknown []string
	for _, n := range body.DisabledTools {
		if !knownTool(n) {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		writeErr(w, http.StatusBadRequest, "Tool sconosciuti: "+strings.Join(unknown, ", "))
		return
	}
	enc, _ := json.Marshal(body.DisabledTools)
	if err := a.store.SetSetting(mcpDisabledKey, string(enc)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	claims := claimsFrom(r.Context())
	rendered := "[]"
	if len(body.DisabledTools) > 0 {
		rendered = "[" + strings.Join(body.DisabledTools, ", ") + "]"
	}
	a.auditLog("Tool MCP disabilitati impostati a " + rendered + " dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

func (a *App) handleGetMCPToolConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"disabled_tools": a.mcpDisabledTools()})
}
