// Package api: handler dei profili di connessione AI e dell'elenco modelli.
// Porta della parte profili/modelli di routers/ai.py. Le chiavi API sono
// cifrate a riposo nel Vault e i profili sono persistiti come JSON nella
// tabella settings (KV).
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"

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

var _ = ai.GetDefaultModel // usato nei task successivi
