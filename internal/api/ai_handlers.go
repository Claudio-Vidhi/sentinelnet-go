// Package api: handler dei profili di connessione AI e dell'elenco modelli.
// Porta della parte profili/modelli di routers/ai.py. Le chiavi API sono
// cifrate a riposo nel Vault e i profili sono persistiti come JSON nella
// tabella settings (KV).
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/ai"
)

const (
	aiProfilesKey      = "ai_profiles"
	aiActiveProfileKey = "ai_active_profile"
)

var aiProviders = map[string]bool{
	"anthropic": true, "openai": true, "gemini": true, "ollama": true,
}

type aiProfile struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	BaseURL            string `json:"base_url"`
	APIKeyEnc          string `json:"api_key_enc"`
	RateLimitRPM       int    `json:"rate_limit_rpm"`
	AllowUnredacted    bool   `json:"allow_unredacted"`
	ContextBudgetChars int    `json:"context_budget_chars"`
}

// loadProfiles legge la lista dei profili e l'id di quello attivo dalle
// settings. Nessuna migrazione dal vecchio formato singolo: il port Go parte
// da lista vuota quando le chiavi mancano (Divergenze §14).
func (a *App) loadProfiles() ([]aiProfile, string) {
	var list []aiProfile
	if raw := a.store.GetSetting(aiProfilesKey, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &list)
	}
	return list, a.store.GetSetting(aiActiveProfileKey, "")
}

func (a *App) saveProfiles(list []aiProfile, active string) error {
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := a.store.SetSetting(aiProfilesKey, string(b)); err != nil {
		return err
	}
	return a.store.SetSetting(aiActiveProfileKey, active)
}

func findProfile(list []aiProfile, id string) *aiProfile {
	if id == "" {
		return nil
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}

// maskProfile: rappresentazione sicura da esporre via API — mai la chiave.
func maskProfile(p aiProfile) map[string]any {
	return map[string]any{
		"id":                   p.ID,
		"name":                 p.Name,
		"provider":             p.Provider,
		"model":                p.Model,
		"base_url":             p.BaseURL,
		"api_key_set":          p.APIKeyEnc != "",
		"rate_limit_rpm":       p.RateLimitRPM,
		"allow_unredacted":     p.AllowUnredacted,
		"context_budget_chars": p.ContextBudgetChars,
	}
}

func newProfileID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// assertUnredactedAllowed rifiuta il flag allow_unredacted sui provider NON
// locali: le config non redatte possono raggiungere solo LLM locali fidati
// (fail-closed), come in Python _assert_unredacted_allowed.
func assertUnredactedAllowed(allow bool, provider, baseURL string) error {
	if !allow {
		return nil
	}
	p := strings.ToLower(strings.TrimSpace(provider))
	if p == "ollama" || (p == "openai" && ai.IsLocalBaseURL(baseURL)) {
		return nil
	}
	return errors.New("L'invio di configurazioni non redatte è consentito solo verso LLM locali " +
		"(provider 'ollama' o endpoint OpenAI-compatible su host locale/privato).")
}

func clampNonNeg(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

type aiProfileReq struct {
	Name               string `json:"name"`
	Provider           string `json:"provider"`
	Model              string `json:"model"`
	APIKey             string `json:"api_key"`
	BaseURL            string `json:"base_url"`
	RateLimitRPM       int    `json:"rate_limit_rpm"`
	AllowUnredacted    bool   `json:"allow_unredacted"`
	ContextBudgetChars int    `json:"context_budget_chars"`
}

// handleListAIProfiles: GET /api/ai/profiles (admin). Chiavi mascherate.
func (a *App) handleListAIProfiles(w http.ResponseWriter, r *http.Request) {
	list, active := a.loadProfiles()
	masked := make([]map[string]any, 0, len(list))
	for _, p := range list {
		masked = append(masked, maskProfile(p))
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": masked, "active_profile": active})
}

// handleCreateAIProfile: POST /api/ai/profiles (admin).
func (a *App) handleCreateAIProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req aiProfileReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if !aiProviders[provider] {
		writeErr(w, http.StatusBadRequest, "Provider non supportato: '"+provider+"'.")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "Il nome del profilo è obbligatorio.")
		return
	}
	if err := assertUnredactedAllowed(req.AllowUnredacted, provider, req.BaseURL); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	enc := ""
	if req.APIKey != "" {
		var err error
		if enc, err = a.vault.Encrypt(req.APIKey); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	list, active := a.loadProfiles()
	p := aiProfile{
		ID:                 newProfileID(),
		Name:               name,
		Provider:           provider,
		Model:              strings.TrimSpace(req.Model),
		BaseURL:            strings.TrimSpace(req.BaseURL),
		APIKeyEnc:          enc,
		RateLimitRPM:       clampNonNeg(req.RateLimitRPM),
		AllowUnredacted:    req.AllowUnredacted,
		ContextBudgetChars: clampNonNeg(req.ContextBudgetChars),
	}
	list = append(list, p)
	if active == "" {
		active = p.ID
	}
	if err := a.saveProfiles(list, active); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Profilo AI '" + p.Name + "' creato (provider='" + provider + "') dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, maskProfile(p))
}
