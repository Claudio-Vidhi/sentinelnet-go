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
	"github.com/go-chi/chi/v5"
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

type aiProfileUpdateReq struct {
	Name               *string `json:"name"`
	Provider           *string `json:"provider"`
	Model              *string `json:"model"`
	APIKey             *string `json:"api_key"`
	BaseURL            *string `json:"base_url"`
	RateLimitRPM       *int    `json:"rate_limit_rpm"`
	AllowUnredacted    *bool   `json:"allow_unredacted"`
	ContextBudgetChars *int    `json:"context_budget_chars"`
}

// handleUpdateAIProfile: PUT /api/ai/profiles/{id} (admin). Aggiornamento
// parziale: campo assente/null = non modificare; api_key="" rimuove la chiave.
func (a *App) handleUpdateAIProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req aiProfileUpdateReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	list, active := a.loadProfiles()
	p := findProfile(list, chi.URLParam(r, "id"))
	if p == nil {
		writeErr(w, http.StatusNotFound, "Profilo AI non trovato.")
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeErr(w, http.StatusBadRequest, "Il nome del profilo è obbligatorio.")
			return
		}
		p.Name = name
	}
	if req.Provider != nil {
		provider := strings.ToLower(strings.TrimSpace(*req.Provider))
		if !aiProviders[provider] {
			writeErr(w, http.StatusBadRequest, "Provider non supportato: '"+provider+"'.")
			return
		}
		p.Provider = provider
	}
	if req.Model != nil {
		p.Model = strings.TrimSpace(*req.Model)
	}
	if req.BaseURL != nil {
		p.BaseURL = strings.TrimSpace(*req.BaseURL)
	}
	if req.RateLimitRPM != nil {
		p.RateLimitRPM = clampNonNeg(*req.RateLimitRPM)
	}
	if req.ContextBudgetChars != nil {
		p.ContextBudgetChars = clampNonNeg(*req.ContextBudgetChars)
	}
	// api_key nil = mantiene; "" = rimuove; valore = cifra e sostituisce.
	if req.APIKey != nil {
		if *req.APIKey == "" {
			p.APIKeyEnc = ""
		} else {
			enc, err := a.vault.Encrypt(*req.APIKey)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			p.APIKeyEnc = enc
		}
	}
	if req.AllowUnredacted != nil {
		p.AllowUnredacted = *req.AllowUnredacted
	}
	// Difesa in profondità: il flag non-redatto è valido solo su provider locali.
	if err := assertUnredactedAllowed(p.AllowUnredacted, p.Provider, p.BaseURL); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.saveProfiles(list, active); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Profilo AI '" + p.Name + "' aggiornato dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, maskProfile(*p))
}

// handleDeleteAIProfile: DELETE /api/ai/profiles/{id} (admin). Se il profilo
// era attivo, l'attivo passa al primo rimanente (o vuoto se non ne restano).
func (a *App) handleDeleteAIProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	id := chi.URLParam(r, "id")
	list, active := a.loadProfiles()
	p := findProfile(list, id)
	if p == nil {
		writeErr(w, http.StatusNotFound, "Profilo AI non trovato.")
		return
	}
	name := p.Name
	remaining := make([]aiProfile, 0, len(list))
	for _, e := range list {
		if e.ID != id {
			remaining = append(remaining, e)
		}
	}
	if active == id {
		active = ""
		if len(remaining) > 0 {
			active = remaining[0].ID
		}
	}
	if err := a.saveProfiles(remaining, active); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Profilo AI '" + name + "' eliminato dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success"})
}

// handleActivateAIProfile: POST /api/ai/profiles/{id}/activate (admin).
func (a *App) handleActivateAIProfile(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	id := chi.URLParam(r, "id")
	list, _ := a.loadProfiles()
	p := findProfile(list, id)
	if p == nil {
		writeErr(w, http.StatusNotFound, "Profilo AI non trovato.")
		return
	}
	if err := a.saveProfiles(list, id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.auditLog("Profilo AI attivo impostato su '" + p.Name + "' dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{"status": "success", "active_profile": id})
}

// handleListAIModels: GET /api/ai/models?provider=&profile_id= (admin).
// Elenca i modelli chat di un provider usando chiave/base_url del profilo
// indicato o di quello attivo. Porta di list_ai_models.
func (a *App) handleListAIModels(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, active := a.loadProfiles()
	profile := findProfile(list, q.Get("profile_id"))
	if profile == nil {
		profile = findProfile(list, active)
	}
	prov := strings.ToLower(strings.TrimSpace(q.Get("provider")))
	if prov == "" && profile != nil {
		prov = strings.ToLower(strings.TrimSpace(profile.Provider))
	}
	if prov == "" {
		writeErr(w, http.StatusBadRequest, "Nessun provider AI configurato.")
		return
	}
	// Se il profilo risolto usa un altro provider, preferisci un profilo che
	// usi 'prov' e abbia una chiave (o sia ollama), per validarlo prima di salvarlo.
	if profile != nil && strings.ToLower(strings.TrimSpace(profile.Provider)) != prov {
		for i := range list {
			pv := strings.ToLower(strings.TrimSpace(list[i].Provider))
			if pv == prov && (list[i].APIKeyEnc != "" || prov == "ollama") {
				profile = &list[i]
				break
			}
		}
	}
	apiKey := ""
	baseURL := ""
	if profile != nil {
		if profile.APIKeyEnc != "" {
			dec, err := a.vault.Decrypt(profile.APIKeyEnc)
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			apiKey = dec
		}
		baseURL = profile.BaseURL
	}
	models, err := ai.ListModels(prov, apiKey, baseURL)
	if err != nil {
		var e *ai.Error
		if errors.As(err, &e) {
			writeErr(w, http.StatusBadGateway, e.Error())
			return
		}
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"provider":      prov,
		"models":        models,
		"default_model": ai.GetDefaultModel(prov),
	})
}
