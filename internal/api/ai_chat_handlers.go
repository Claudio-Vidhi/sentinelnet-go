// Package api: endpoint dell'AI Assistant (/api/ai/chat, /api/ai/generate-config).
// Porta di ai_chat e ai_generate_config di routers/ai.py. Assembla il contesto
// dai builder di ai_context.go, rispetta il budget caratteri e delega a
// internal/ai.Chat (che applica il choke-point di redazione).
package api

import (
	"errors"
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"
)

type aiChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type flowKeySchema struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	Protocol int    `json:"protocol"`
	DstPort  *int   `json:"dst_port"`
}

type aiChatReq struct {
	Messages          []aiChatMessage `json:"messages"`
	AttachInventory   bool            `json:"attach_inventory"`
	AttachDeviceIP    string          `json:"attach_device_ip"`
	AttachTenant      string          `json:"attach_tenant"`
	AttachFortigateIP string          `json:"attach_fortigate_ip"`
	AttachTopFlows    bool            `json:"attach_top_flows"`
	AttachFlowKeys    []flowKeySchema `json:"attach_flow_keys"`
	AttachDeviceIPs   []string        `json:"attach_device_ips"`
}

type aiGenerateConfigReq struct {
	Tenant     string `json:"tenant"`
	Hostname   string `json:"hostname"`
	MgmtIP     string `json:"mgmt_ip"`
	TemplateIP string `json:"template_ip"`
	Notes      string `json:"notes"`
}

// activeProfile ritorna il profilo AI attivo o nil.
func (a *App) activeProfile() *aiProfile {
	list, active := a.loadProfiles()
	return findProfile(list, active)
}

// chatProfileAndKey risolve il profilo attivo e la sua chiave decifrata,
// scrivendo la risposta d'errore e ritornando ok=false se manca il profilo o
// (per provider non-ollama) la chiave. Condiviso da chat e generate-config.
func (a *App) chatProfileAndKey(w http.ResponseWriter) (*aiProfile, string, bool) {
	profile := a.activeProfile()
	if profile == nil {
		writeErr(w, http.StatusBadRequest, "Nessun profilo AI configurato/attivo. Un amministratore deve crearne uno prima.")
		return nil, "", false
	}
	apiKey := ""
	if profile.APIKeyEnc != "" {
		dec, err := a.vault.Decrypt(profile.APIKeyEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return nil, "", false
		}
		apiKey = dec
	}
	if profile.Provider != "ollama" && apiKey == "" {
		writeErr(w, http.StatusBadRequest, "API key non configurata per il profilo AI attivo.")
		return nil, "", false
	}
	return profile, apiKey, true
}

// chatModelName: modello effettivo per la risposta (default per-provider se il
// profilo non ne fissa uno).
func chatModelName(profile *aiProfile) string {
	if profile.Model != "" {
		return profile.Model
	}
	return ai.GetDefaultModel(profile.Provider)
}

// runChat esegue ai.Chat con le opzioni del profilo e mappa gli errori
// (RateLimit → 429, Error → 502). Ritorna (reply, ok); su errore ha già scritto.
func (a *App) runChat(w http.ResponseWriter, profile *aiProfile, apiKey string, messages []ai.Message) (string, bool) {
	reply, err := ai.Chat(messages, ai.ChatOptions{
		Provider:        profile.Provider,
		Model:           profile.Model,
		APIKey:          apiKey,
		BaseURL:         profile.BaseURL,
		RateLimitRPM:    &profile.RateLimitRPM,
		AllowUnredacted: profile.AllowUnredacted,
	})
	if err != nil {
		var rl *ai.RateLimitError
		if errors.As(err, &rl) {
			writeErr(w, http.StatusTooManyRequests, rl.Error())
			return "", false
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return "", false
	}
	return reply, true
}

// handleAIChat: POST /api/ai/chat (utente autenticato). In questa fase gestisce
// profilo, chiave e la chat senza contesto; l'assemblaggio del contesto è
// aggiunto nei task successivi.
func (a *App) handleAIChat(w http.ResponseWriter, r *http.Request) {
	profile, apiKey, ok := a.chatProfileAndKey(w)
	if !ok {
		return
	}
	var req aiChatReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	messages := make([]ai.Message, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = ai.Message{Role: m.Role, Content: m.Content}
	}
	reply, ok := a.runChat(w, profile, apiKey, messages)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"reply": reply, "provider": profile.Provider,
		"model": chatModelName(profile), "profile_name": profile.Name,
	})
}
