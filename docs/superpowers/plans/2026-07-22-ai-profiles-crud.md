# AI Profile CRUD + Models Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the AI profile CRUD and models-list endpoints from `routers/ai.py` to the Go server, admin-only, with vault-encrypted API keys.

**Architecture:** One new file `internal/api/ai_handlers.go`. Profiles persist as a JSON array in the existing `settings` KV table (keys `ai_profiles` and `ai_active_profile`). Handlers register in `router.go` behind `requireAuth("admin", …)`. No new package, no SQL migration.

**Tech Stack:** Go stdlib `net/http` (1.22 routing, `r.PathValue`), `encoding/json`, existing `crypto.Vault`, `store.Store` KV settings, `internal/ai` (`ListModels`, `GetDefaultModel`, `IsLocalBaseURL`, `*ai.Error`).

## Global Constraints

- Every profile/models endpoint is admin-only: register with `a.requireAuth("admin", handler)`.
- API keys are never returned in plaintext and `api_key_enc` is never emitted by any handler.
- Comments and audit-log strings in Italian, matching the surrounding codebase.
- Providers set is exactly `{"anthropic","openai","gemini","ollama"}`.
- `rate_limit_rpm` and `context_budget_chars` are clamped with `max(0, v)`.
- Response bodies match `routers/ai.py` field-for-field.
- Reference spec: `docs/superpowers/specs/2026-07-22-ai-profiles-crud-design.md`.

---

## File Structure

- **Create** `internal/api/ai_handlers.go` — struct, store helpers, mask, unredacted gate, all six handlers.
- **Create** `internal/api/ai_handlers_test.go` — httptest coverage.
- **Modify** `internal/api/router.go` — register six routes.
- **Modify** `docs/DIVERGENZE-DAL-PYTHON.md` — add §14.

---

### Task 1: Profile model, store helpers, and mask

**Files:**
- Create: `internal/api/ai_handlers.go`
- Test: `internal/api/ai_handlers_test.go`

**Interfaces:**
- Consumes: `store.Store.GetSetting(key, def string) string`, `store.Store.SetSetting(key, value string) error`.
- Produces:
  - `type aiProfile struct { ID, Name, Provider, Model, BaseURL, APIKeyEnc string; RateLimitRPM int; AllowUnredacted bool; ContextBudgetChars int }` with json tags per spec.
  - `func (a *App) loadProfiles() ([]aiProfile, string)`
  - `func (a *App) saveProfiles(list []aiProfile, active string) error`
  - `func findProfile(list []aiProfile, id string) *aiProfile`
  - `func maskProfile(p aiProfile) map[string]any`
  - `func newProfileID() string` (32 hex chars)
  - `var aiProviders = map[string]bool{"anthropic":true,"openai":true,"gemini":true,"ollama":true}`
  - const `aiProfilesKey = "ai_profiles"`, `aiActiveProfileKey = "ai_active_profile"`

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"encoding/base64"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	key, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault)
}

func TestProfilesEmptyByDefault(t *testing.T) {
	app := newTestApp(t)
	list, active := app.loadProfiles()
	if len(list) != 0 || active != "" {
		t.Fatalf("want empty list and no active, got %d profiles active=%q", len(list), active)
	}
}

func TestSaveLoadFindRoundtrip(t *testing.T) {
	app := newTestApp(t)
	p := aiProfile{ID: newProfileID(), Name: "p1", Provider: "ollama", APIKeyEnc: "secret-enc"}
	if err := app.saveProfiles([]aiProfile{p}, p.ID); err != nil {
		t.Fatal(err)
	}
	list, active := app.loadProfiles()
	if len(list) != 1 || active != p.ID {
		t.Fatalf("roundtrip mismatch: %d profiles active=%q", len(list), active)
	}
	if findProfile(list, p.ID) == nil {
		t.Error("findProfile should locate saved profile")
	}
	if findProfile(list, "nope") != nil || findProfile(list, "") != nil {
		t.Error("findProfile must return nil for missing/empty id")
	}
}

func TestMaskNeverExposesKey(t *testing.T) {
	m := maskProfile(aiProfile{ID: "x", Name: "n", Provider: "openai", APIKeyEnc: "ciphertext"})
	if _, ok := m["api_key_enc"]; ok {
		t.Error("mask must not include api_key_enc")
	}
	if _, ok := m["api_key"]; ok {
		t.Error("mask must not include api_key")
	}
	if m["api_key_set"] != true {
		t.Error("api_key_set should be true when key present")
	}
	if maskProfile(aiProfile{})["api_key_set"] != false {
		t.Error("api_key_set should be false when key absent")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run 'TestProfilesEmptyByDefault|TestSaveLoadFindRoundtrip|TestMaskNeverExposesKey'`
Expected: FAIL — compile error, `aiProfile`/`loadProfiles`/etc. undefined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/api/ai_handlers.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run 'TestProfilesEmptyByDefault|TestSaveLoadFindRoundtrip|TestMaskNeverExposesKey'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_handlers.go internal/api/ai_handlers_test.go
git commit -m "feat(ai): storage profili + mask (2b task 1)"
```

---

### Task 2: Unredacted gate and small helpers

**Files:**
- Modify: `internal/api/ai_handlers.go`
- Test: `internal/api/ai_handlers_test.go`

**Interfaces:**
- Consumes: `ai.IsLocalBaseURL(baseURL string) bool`.
- Produces:
  - `func assertUnredactedAllowed(allow bool, provider, baseURL string) error` — returns `nil` if allowed, else an error whose `.Error()` is the Italian "solo LLM locali" message.
  - `func clampNonNeg(v int) int` — returns `max(0, v)`.

- [ ] **Step 1: Write the failing test**

```go
func TestAssertUnredactedAllowed(t *testing.T) {
	if assertUnredactedAllowed(false, "anthropic", "") != nil {
		t.Error("allow=false must always pass")
	}
	if assertUnredactedAllowed(true, "ollama", "") != nil {
		t.Error("ollama must be allowed")
	}
	if assertUnredactedAllowed(true, "openai", "http://127.0.0.1:1234/v1") != nil {
		t.Error("openai on local base_url must be allowed")
	}
	if assertUnredactedAllowed(true, "openai", "https://api.openai.com/v1") == nil {
		t.Error("openai on remote base_url must be rejected")
	}
	if assertUnredactedAllowed(true, "anthropic", "") == nil {
		t.Error("anthropic must be rejected")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestAssertUnredactedAllowed`
Expected: FAIL — `assertUnredactedAllowed` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/ai_handlers.go` (and add `"errors"` and `"strings"` to imports):

```go
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
```

Remove the `var _ = ai.GetDefaultModel` placeholder line from Task 1 (still unused until Task 6 — re-add it at the bottom if `go vet` complains about an unused import; the import `ai` is now used by `assertUnredactedAllowed`, so the placeholder can be deleted).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestAssertUnredactedAllowed`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_handlers.go internal/api/ai_handlers_test.go
git commit -m "feat(ai): gate non-redatto + clamp (2b task 2)"
```

---

### Task 3: GET and POST /api/ai/profiles + route registration

**Files:**
- Modify: `internal/api/ai_handlers.go`
- Modify: `internal/api/router.go`
- Test: `internal/api/ai_handlers_test.go`

**Interfaces:**
- Consumes: `decodeJSON`, `writeJSON`, `writeErr`, `claimsFrom`, `a.auditLog`, `a.vault.Encrypt`, helpers from Tasks 1–2.
- Produces:
  - `func (a *App) handleListAIProfiles(w http.ResponseWriter, r *http.Request)`
  - `func (a *App) handleCreateAIProfile(w http.ResponseWriter, r *http.Request)`

- [ ] **Step 1: Write the failing test**

```go
import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
)

func adminReq(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewReader([]byte(body)))
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
}

func TestCreateAndListProfile(t *testing.T) {
	app := newTestApp(t)

	// Nome vuoto → 400.
	rec := httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles", `{"name":"","provider":"ollama"}`))
	if rec.Code != 400 {
		t.Fatalf("empty name: status = %d, want 400", rec.Code)
	}

	// Provider non valido → 400.
	rec = httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles", `{"name":"x","provider":"foo"}`))
	if rec.Code != 400 {
		t.Fatalf("bad provider: status = %d, want 400", rec.Code)
	}

	// unredacted su provider remoto → 400.
	rec = httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
		`{"name":"x","provider":"anthropic","allow_unredacted":true}`))
	if rec.Code != 400 {
		t.Fatalf("unredacted remote: status = %d, want 400", rec.Code)
	}

	// Creazione valida con chiave.
	rec = httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
		`{"name":"Primo","provider":"anthropic","api_key":"sk-123","rate_limit_rpm":-5}`))
	if rec.Code != 200 {
		t.Fatalf("create: status = %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created["api_key_set"] != true || created["rate_limit_rpm"] != float64(0) {
		t.Errorf("created payload wrong: %+v", created)
	}
	if _, ok := created["api_key_enc"]; ok {
		t.Error("create response must not leak api_key_enc")
	}

	// Il primo profilo diventa attivo; la chiave è cifrata a riposo.
	list, active := app.loadProfiles()
	if len(list) != 1 || active != list[0].ID {
		t.Fatalf("first profile should be active: %d active=%q", len(list), active)
	}
	if list[0].APIKeyEnc == "" || list[0].APIKeyEnc == "sk-123" {
		t.Errorf("api key must be stored encrypted, got %q", list[0].APIKeyEnc)
	}

	// List riporta il profilo mascherato e l'attivo.
	rec = httptest.NewRecorder()
	app.handleListAIProfiles(rec, adminReq("GET", "/api/ai/profiles", ""))
	var lst map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &lst)
	if lst["active_profile"] != active {
		t.Errorf("active_profile = %v, want %v", lst["active_profile"], active)
	}
	if profs, _ := lst["profiles"].([]any); len(profs) != 1 {
		t.Errorf("profiles length = %d, want 1", len(profs))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestCreateAndListProfile`
Expected: FAIL — handlers undefined.

- [ ] **Step 3: Write minimal implementation**

Add `"net/http"` to imports. Add to `internal/api/ai_handlers.go`:

```go
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
```

Register routes in `internal/api/router.go` next to the `/api/settings/app` block:

```go
	r.Get("/api/ai/profiles", a.requireAuth("admin", a.handleListAIProfiles))
	r.Post("/api/ai/profiles", a.requireAuth("admin", a.handleCreateAIProfile))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestCreateAndListProfile`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_handlers.go internal/api/router.go internal/api/ai_handlers_test.go
git commit -m "feat(ai): GET/POST profili + rotte (2b task 3)"
```

---

### Task 4: PUT /api/ai/profiles/{id} — partial update

**Files:**
- Modify: `internal/api/ai_handlers.go`
- Modify: `internal/api/router.go`
- Test: `internal/api/ai_handlers_test.go`

**Interfaces:**
- Consumes: `chi.URLParam(r, "id")`, helpers from Tasks 1–3.
- Produces:
  - `func (a *App) handleUpdateAIProfile(w http.ResponseWriter, r *http.Request)`.
  - test helper `func withIDParam(r *http.Request, id string) *http.Request` (injects chi route param `{id}`, preserving existing context/claims).
- Uses pointer fields so absent≠null≠empty; `api_key: null`=keep, `""`=remove, value=replace.

- [ ] **Step 1: Write the failing test**

Add `"github.com/go-chi/chi/v5"` to the test imports, plus this shared helper (defined once, reused in Task 5):

```go
// withIDParam inietta il parametro di rotta chi {id} preservando i claims già
// impostati da adminReq (stesso pattern di withIPParam in fortigate_handlers_test.go).
func withIDParam(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func TestUpdateProfilePartial(t *testing.T) {
	app := newTestApp(t)
	// Seed un profilo con chiave.
	rec := httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
		`{"name":"P","provider":"anthropic","api_key":"sk-orig"}`))
	list, _ := app.loadProfiles()
	id := list[0].ID
	origEnc := list[0].APIKeyEnc

	call := func(body string) *httptest.ResponseRecorder {
		req := withIDParam(adminReq("PUT", "/api/ai/profiles/"+id, body), id)
		rec := httptest.NewRecorder()
		app.handleUpdateAIProfile(rec, req)
		return rec
	}

	// api_key assente → chiave invariata; cambia solo il nome.
	if rec := call(`{"name":"Nuovo"}`); rec.Code != 200 {
		t.Fatalf("update name: %d %s", rec.Code, rec.Body.String())
	}
	list, _ = app.loadProfiles()
	if list[0].Name != "Nuovo" || list[0].APIKeyEnc != origEnc {
		t.Errorf("name update should keep key: name=%q key=%q", list[0].Name, list[0].APIKeyEnc)
	}

	// api_key="" → rimuove la chiave.
	if rec := call(`{"api_key":""}`); rec.Code != 200 {
		t.Fatalf("clear key: %d", rec.Code)
	}
	list, _ = app.loadProfiles()
	if list[0].APIKeyEnc != "" {
		t.Error("empty api_key should remove stored key")
	}

	// nome vuoto esplicito → 400.
	if rec := call(`{"name":"  "}`); rec.Code != 400 {
		t.Errorf("blank name: status = %d, want 400", rec.Code)
	}

	// id inesistente → 404.
	rec = httptest.NewRecorder()
	app.handleUpdateAIProfile(rec, withIDParam(adminReq("PUT", "/api/ai/profiles/zzz", `{"name":"x"}`), "zzz"))
	if rec.Code != 404 {
		t.Errorf("missing id: status = %d, want 404", rec.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestUpdateProfilePartial`
Expected: FAIL — `handleUpdateAIProfile` undefined.

- [ ] **Step 3: Write minimal implementation**

Add `"github.com/go-chi/chi/v5"` to the imports of `internal/api/ai_handlers.go`, then add:

```go
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
```

Register route in `router.go`:

```go
	r.Put("/api/ai/profiles/{id}", a.requireAuth("admin", a.handleUpdateAIProfile))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestUpdateProfilePartial`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_handlers.go internal/api/router.go internal/api/ai_handlers_test.go
git commit -m "feat(ai): PUT aggiornamento parziale profilo (2b task 4)"
```

---

### Task 5: DELETE and activate

**Files:**
- Modify: `internal/api/ai_handlers.go`
- Modify: `internal/api/router.go`
- Test: `internal/api/ai_handlers_test.go`

**Interfaces:**
- Consumes: `chi.URLParam(r, "id")`, `withIDParam` (Task 4), helpers from Tasks 1–3.
- Produces:
  - `func (a *App) handleDeleteAIProfile(w http.ResponseWriter, r *http.Request)`
  - `func (a *App) handleActivateAIProfile(w http.ResponseWriter, r *http.Request)`

- [ ] **Step 1: Write the failing test**

```go
func TestDeleteAndActivate(t *testing.T) {
	app := newTestApp(t)
	mk := func(name string) string {
		rec := httptest.NewRecorder()
		app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
			`{"name":"`+name+`","provider":"ollama"}`))
		var m map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &m)
		return m["id"].(string)
	}
	id1 := mk("A") // diventa attivo
	id2 := mk("B")

	// activate id2.
	rec := httptest.NewRecorder()
	app.handleActivateAIProfile(rec, withIDParam(adminReq("POST", "/api/ai/profiles/"+id2+"/activate", ""), id2))
	if rec.Code != 200 {
		t.Fatalf("activate: %d %s", rec.Code, rec.Body.String())
	}
	if _, active := app.loadProfiles(); active != id2 {
		t.Fatalf("active = %q, want %q", active, id2)
	}

	// delete id2 (attivo) → ripiega sul primo rimanente (id1).
	rec = httptest.NewRecorder()
	app.handleDeleteAIProfile(rec, withIDParam(adminReq("DELETE", "/api/ai/profiles/"+id2, ""), id2))
	if rec.Code != 200 {
		t.Fatalf("delete: %d", rec.Code)
	}
	list, active := app.loadProfiles()
	if len(list) != 1 || active != id1 {
		t.Fatalf("after delete: %d profiles active=%q want %q", len(list), active, id1)
	}

	// delete id inesistente → 404.
	rec = httptest.NewRecorder()
	app.handleDeleteAIProfile(rec, withIDParam(adminReq("DELETE", "/api/ai/profiles/zzz", ""), "zzz"))
	if rec.Code != 404 {
		t.Errorf("missing delete: status = %d, want 404", rec.Code)
	}

	// activate id inesistente → 404.
	rec = httptest.NewRecorder()
	app.handleActivateAIProfile(rec, withIDParam(adminReq("POST", "/api/ai/profiles/zzz/activate", ""), "zzz"))
	if rec.Code != 404 {
		t.Errorf("missing activate: status = %d, want 404", rec.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestDeleteAndActivate`
Expected: FAIL — handlers undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/ai_handlers.go`:

```go
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
```

Register routes in `router.go`:

```go
	r.Delete("/api/ai/profiles/{id}", a.requireAuth("admin", a.handleDeleteAIProfile))
	r.Post("/api/ai/profiles/{id}/activate", a.requireAuth("admin", a.handleActivateAIProfile))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/api/ -run TestDeleteAndActivate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_handlers.go internal/api/router.go internal/api/ai_handlers_test.go
git commit -m "feat(ai): DELETE + activate profilo (2b task 5)"
```

---

### Task 6: GET /api/ai/models

**Files:**
- Modify: `internal/api/ai_handlers.go`
- Modify: `internal/api/router.go`
- Test: `internal/api/ai_handlers_test.go`

**Interfaces:**
- Consumes: `r.URL.Query()`, `a.vault.Decrypt`, `ai.ListModels`, `ai.GetDefaultModel`, `*ai.Error`.
- Produces: `func (a *App) handleListAIModels(w http.ResponseWriter, r *http.Request)`.

- [ ] **Step 1: Write the failing test**

```go
func TestListAIModelsResolvesProfile(t *testing.T) {
	// Endpoint ollama finto: risponde a /api/tags.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			_, _ = w.Write([]byte(`{"models":[{"name":"llama3"},{"name":"qwen"}]}`))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)

	app := newTestApp(t)
	rec := httptest.NewRecorder()
	app.handleCreateAIProfile(rec, adminReq("POST", "/api/ai/profiles",
		`{"name":"O","provider":"ollama","base_url":"`+srv.URL+`"}`))
	if rec.Code != 200 {
		t.Fatalf("seed profile: %d %s", rec.Code, rec.Body.String())
	}

	// Nessun provider/profile_id: usa il profilo attivo (ollama).
	rec = httptest.NewRecorder()
	app.handleListAIModels(rec, adminReq("GET", "/api/ai/models", ""))
	if rec.Code != 200 {
		t.Fatalf("models: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["provider"] != "ollama" {
		t.Errorf("provider = %v", out["provider"])
	}
	models, _ := out["models"].([]any)
	if len(models) != 2 {
		t.Errorf("models length = %d, want 2", len(models))
	}
	if out["default_model"] != ai.GetDefaultModel("ollama") {
		t.Errorf("default_model = %v", out["default_model"])
	}
}

func TestListAIModelsNoProviderIsError(t *testing.T) {
	app := newTestApp(t) // nessun profilo, nessuna query provider
	rec := httptest.NewRecorder()
	app.handleListAIModels(rec, adminReq("GET", "/api/ai/models", ""))
	if rec.Code != 400 {
		t.Errorf("no provider: status = %d, want 400", rec.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run 'TestListAIModels'`
Expected: FAIL — `handleListAIModels` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/ai_handlers.go` (`ai.Error` needs `"errors"` — already imported in Task 2):

```go
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
```

Register route in `router.go`:

```go
	r.Get("/api/ai/models", a.requireAuth("admin", a.handleListAIModels))
```

- [ ] **Step 4: Run test to verify it passes and the whole package builds**

Run: `go test ./internal/api/ -run 'TestListAIModels'`
Expected: PASS.

Run: `go test ./internal/api/`
Expected: PASS (all AI + existing tests).

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_handlers.go internal/api/router.go internal/api/ai_handlers_test.go
git commit -m "feat(ai): GET /api/ai/models con risoluzione profilo (2b task 6)"
```

---

### Task 7: Document divergences

**Files:**
- Modify: `docs/DIVERGENZE-DAL-PYTHON.md`

- [ ] **Step 1: Append section §14**

Add at the end of `docs/DIVERGENZE-DAL-PYTHON.md`:

```markdown
## 14. Profili AI: nessuna migrazione dal formato legacy singolo

`routers/ai.py` (`_get_ai_profiles_raw`) migra, alla prima lettura, il vecchio
dict singolo `ai` di `app_settings.json` nella lista `ai_profiles`. Il server Go
non ha mai scritto quel formato: `loadProfiles` parte da lista vuota quando le
chiavi `ai_profiles`/`ai_active_profile` mancano, senza codice di migrazione.

`rate_limit_rpm` è persistito nel profilo come int semplice (0 = nessun limite).
Il tipo `*int` che distingue None da 0 riguarda solo il passaggio a `chat()`
(unità 2c), non lo storage del profilo.
```

- [ ] **Step 2: Verify full build and vet**

Run: `go build ./... && go vet ./internal/api/`
Expected: no output (success).

- [ ] **Step 3: Commit**

```bash
git add docs/DIVERGENZE-DAL-PYTHON.md
git commit -m "docs: divergenza §14 (profili AI, nessuna migrazione legacy)"
```

---

## Self-Review Notes

- **Spec coverage:** storage helpers (T1), mask (T1), unredacted gate (T2), GET+POST (T3), PUT partial with api_key semantics (T4), DELETE+activate with active-fallback (T5), models with provider resolution + fallback + 502 mapping (T6), divergences §14 (T7). All spec sections mapped.
- **Type consistency:** `aiProfile`, `loadProfiles`/`saveProfiles`/`findProfile`/`maskProfile`, `assertUnredactedAllowed`, `clampNonNeg`, `newProfileID` used with identical signatures across tasks.
- **`ai` import:** first used by `assertUnredactedAllowed` (T2) via `ai.IsLocalBaseURL`; the Task-1 placeholder `var _ = ai.GetDefaultModel` is deleted in T2.
- **Routing:** this codebase uses go-chi, not stdlib 1.22 routing. Handlers read path params with `chi.URLParam(r, "id")` (first needed in T4); tests inject them with the `withIDParam` helper (chi route context), mirroring `withIPParam` in `fortigate_handlers_test.go`. Routes register with `r.Get/Post/Put/Delete` on the chi router.
```
