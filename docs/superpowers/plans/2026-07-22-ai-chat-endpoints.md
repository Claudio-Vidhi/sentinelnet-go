# AI Chat + Generate-Config Endpoints Implementation Plan (unit 2c-2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port `/api/ai/chat` and `/api/ai/generate-config` from `routers/ai.py` into the Go server, wiring the 2c-1 context builders and 2b profiles into `ai.Chat`. Completes the AI Assistant.

**Architecture:** One new file `internal/api/ai_chat_handlers.go` (methods on `*App`), two routes in `router.go` under `requireAuth("", …)` (any authenticated user). Consumes existing helpers: `loadProfiles`/`findProfile` (2b), `deviceInventorySummary`/`deviceRunningConfigContext`/`fortigateLiveContext`/`tenantContextBlock`/`tenantCommonParameters`/`topFlowsContext`/`assertGroupAllowed` (2c-1), `ai.Chat`/`ContextCharBudget`/`FitContext`/`GetDefaultModel`/`Message`/`ChatOptions`/`Error`/`RateLimitError`.

**Tech Stack:** Go stdlib `net/http`, `encoding/json`, go-chi, `internal/{ai,obsstore}`.

## Global Constraints

- Both routes: `a.requireAuth("", handler)` (authenticated any role) — Python `get_current_user`.
- Error/message strings verbatim from `routers/ai.py`. Comments Italian.
- Fallible context builders return `(string,bool)` and already wrote the HTTP error on `!ok`; the handler must `return` immediately (no further writes).
- The config-proposal instruction block is kept OUT of the char budget (never truncated).
- `RateLimitRPM` passed to `ai.Chat` as `&profile.RateLimitRPM`.
- Error mapping: `*ai.RateLimitError` → 429, `*ai.Error` → 502.
- Reference spec: `docs/superpowers/specs/2026-07-22-ai-chat-endpoints-design.md`. Python source: `routers/ai.py` (`ai_chat`, `ai_generate_config`).

---

## File Structure

- **Create** `internal/api/ai_chat_handlers.go` — request types, `activeProfile`, both handlers.
- **Create** `internal/api/ai_chat_handlers_test.go` — httptest coverage with a fake ollama server.
- **Modify** `internal/api/router.go` — register the two routes.

---

### Task 1: Chat pipeline core (profile + ai.Chat + errors)

**Files:**
- Create: `internal/api/ai_chat_handlers.go`
- Create: `internal/api/ai_chat_handlers_test.go`
- Modify: `internal/api/router.go`

**Interfaces:**
- Consumes: `a.loadProfiles`, `findProfile`, `a.vault.Decrypt`, `claimsFrom`, `decodeJSON`, `writeJSON`, `writeErr`, `ai.Message`, `ai.Chat`, `ai.ChatOptions`, `ai.GetDefaultModel`, `ai.Error`, `ai.RateLimitError`.
- Produces:
  - `func (a *App) activeProfile() *aiProfile`
  - request types `aiChatMessage`, `flowKeySchema`, `aiChatReq`, `aiGenerateConfigReq` (full set now; later tasks use the remaining fields)
  - `func (a *App) handleAIChat(w http.ResponseWriter, r *http.Request)` — this task: profile lookup + key check + plain chat (no context assembly yet) + error mapping + response
  - `func (a *App) chatProfileAndKey(w http.ResponseWriter) (*aiProfile, string, bool)` — shared lookup+decrypt+key-check helper (used by both endpoints)

- [ ] **Step 1: Write the failing test**

```go
package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// fakeOllama returns an httptest server answering /api/chat like Ollama and
// capturing the last request payload. reply is echoed back as the assistant msg.
func fakeOllama(t *testing.T, reply string, captured *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/chat" {
			w.WriteHeader(404)
			return
		}
		if captured != nil {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, captured)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"content": reply}})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func chatApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault)
}

// seedOllamaProfile creates and activates an ollama profile pointing at baseURL.
func seedOllamaProfile(t *testing.T, app *App, baseURL string) {
	t.Helper()
	p := aiProfile{ID: newProfileID(), Name: "local", Provider: "ollama", BaseURL: baseURL}
	if err := app.saveProfiles([]aiProfile{p}, p.ID); err != nil {
		t.Fatal(err)
	}
}

func chatReq(body string, role string) *http.Request {
	req := httptest.NewRequest("POST", "/api/ai/chat", strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "u", Role: role}))
}

func TestChatNoProfile(t *testing.T) {
	app := chatApp(t)
	w := httptest.NewRecorder()
	app.handleAIChat(w, chatReq(`{"messages":[{"role":"user","content":"ciao"}]}`, "admin"))
	if w.Code != 400 {
		t.Fatalf("no profile: code=%d, want 400", w.Code)
	}
}

func TestChatBasicReply(t *testing.T) {
	app := chatApp(t)
	srv := fakeOllama(t, "risposta modello", nil)
	seedOllamaProfile(t, app, srv.URL)
	w := httptest.NewRecorder()
	app.handleAIChat(w, chatReq(`{"messages":[{"role":"user","content":"ciao"}]}`, "admin"))
	if w.Code != 200 {
		t.Fatalf("basic chat: code=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["reply"] != "risposta modello" || resp["provider"] != "ollama" {
		t.Errorf("unexpected response: %+v", resp)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestChatNoProfile|TestChatBasicReply'`
Expected: FAIL — `handleAIChat` undefined.

- [ ] **Step 3: Write minimal implementation**

Create `internal/api/ai_chat_handlers.go`:

```go
// Package api: endpoint dell'AI Assistant (/api/ai/chat, /api/ai/generate-config).
// Porta di ai_chat e ai_generate_config di routers/ai.py. Assembla il contesto
// dai builder di ai_context.go, rispetta il budget caratteri e delega a
// internal/ai.Chat (che applica il choke-point di redazione).
package api

import (
	"errors"
	"net/http"
	"strings"

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
```

`obsstore` is NOT imported in this task (it is first used in Task 2). This task's imports are exactly `errors`, `net/http`, `strings`, and the `ai` package.

Register the chat route in `router.go` (next to the other `/api/ai/*` routes):

```go
	r.Post("/api/ai/chat", a.requireAuth("", a.handleAIChat))
```

(The generate-config route is added in Task 4.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestChatNoProfile|TestChatBasicReply' && go build ./...`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_chat_handlers.go internal/api/ai_chat_handlers_test.go internal/api/router.go
git commit -m "feat(ai): /api/ai/chat pipeline core (2c-2 task 1)"
```

---

### Task 2: Chat context assembly + budget

**Files:**
- Modify: `internal/api/ai_chat_handlers.go`
- Test: `internal/api/ai_chat_handlers_test.go`

**Interfaces:**
- Consumes: `a.deviceInventorySummary`, `a.deviceRunningConfigContext`, `a.tenantContextBlock`, `a.fortigateLiveContext`, `a.topFlowsContext`, `a.tenantsForUser`, `claimsFrom`, `ai.ContextCharBudget`, `ai.FitContext`, `obsstore.FlowKey`.
- Produces: context assembly inside `handleAIChat` (before `runChat`), plus `func (a *App) assembleChatContext(w, r, req, profile) ([]ai.Message, bool)` returning the full message slice (system-prepended when there is context) or ok=false if a builder failed.

- [ ] **Step 1: Write the failing test**

```go
func TestChatAttachInventoryInSystemMsg(t *testing.T) {
	app := chatApp(t)
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(app.store.UpsertDevice(&store.Device{IP: "10.0.0.1", Hostname: "sw1", Vendor: "cisco", Tenant: "acme", Site: "central"}))
	var captured map[string]any
	srv := fakeOllama(t, "ok", &captured)
	seedOllamaProfile(t, app, srv.URL)

	w := httptest.NewRecorder()
	app.handleAIChat(w, chatReq(`{"messages":[{"role":"user","content":"che dispositivi ci sono?"}],"attach_inventory":true}`, "admin"))
	if w.Code != 200 {
		t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
	}
	// The fake server must have received a system message containing the inventory.
	msgs, _ := captured["messages"].([]any)
	if len(msgs) < 2 {
		t.Fatalf("expected system+user messages, got %d", len(msgs))
	}
	sys, _ := msgs[0].(map[string]any)
	if sys["role"] != "system" || !strings.Contains(sys["content"].(string), "Inventario dispositivi") {
		t.Errorf("system message missing inventory: %+v", sys)
	}
}

func TestChatTooManyFlowKeys(t *testing.T) {
	app := chatApp(t)
	srv := fakeOllama(t, "ok", nil)
	seedOllamaProfile(t, app, srv.URL)
	keys := make([]string, 21)
	for i := range keys {
		keys[i] = `{"src_ip":"10.0.0.1","dst_ip":"8.8.8.8","protocol":6,"dst_port":443}`
	}
	body := `{"messages":[{"role":"user","content":"x"}],"attach_flow_keys":[` + strings.Join(keys, ",") + `]}`
	w := httptest.NewRecorder()
	app.handleAIChat(w, chatReq(body, "admin"))
	if w.Code != 400 {
		t.Fatalf("too many flow keys: code=%d, want 400", w.Code)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestChatAttachInventoryInSystemMsg|TestChatTooManyFlowKeys'`
Expected: FAIL — context not assembled (system msg absent; 21 keys accepted).

- [ ] **Step 3: Write minimal implementation**

Add `assembleChatContext` and call it in `handleAIChat` between decode and `runChat`. Add imports `"errors"` (if not present) — actually only `ai`/`obsstore` needed here. Replace the message-building block in `handleAIChat` with:

```go
	messages := make([]ai.Message, len(req.Messages))
	for i, m := range req.Messages {
		messages[i] = ai.Message{Role: m.Role, Content: m.Content}
	}
	messages, ok = a.assembleChatContext(w, r, &req, profile, messages)
	if !ok {
		return
	}
	reply, ok := a.runChat(w, profile, apiKey, messages)
```

(Note: `handleAIChat` now declares `ok` from `chatProfileAndKey`; reuse it — change `reply, ok := a.runChat` accordingly, since `ok` already exists. Use `reply, ok2 := a.runChat(...)` if the compiler complains about redeclaration, or restructure so `ok` is reused.)

Add:

```go
// assembleChatContext costruisce i blocchi di contesto dagli attach flag e, se
// presenti, antepone un messaggio di sistema (contesto adattato al budget +
// blocco istruzioni fuori budget). Porta della parte contesto di ai_chat.
func (a *App) assembleChatContext(w http.ResponseWriter, r *http.Request, req *aiChatReq, profile *aiProfile, messages []ai.Message) ([]ai.Message, bool) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)

	var contextBlocks []string
	add := func(s string) { contextBlocks = append(contextBlocks, s) }

	if req.AttachInventory {
		add(a.deviceInventorySummary(scoped))
	}
	if req.AttachDeviceIP != "" {
		block, ok := a.deviceRunningConfigContext(w, r, req.AttachDeviceIP)
		if !ok {
			return nil, false
		}
		add(block)
	}
	for _, ip := range capStrings(req.AttachDeviceIPs, 20) {
		if ip == req.AttachDeviceIP {
			continue
		}
		block, ok := a.deviceRunningConfigContext(w, r, ip)
		if !ok {
			return nil, false
		}
		add(block)
	}
	if req.AttachTenant != "" {
		block, ok := a.tenantContextBlock(w, r, req.AttachTenant)
		if !ok {
			return nil, false
		}
		add(block)
	}
	if req.AttachFortigateIP != "" {
		block, ok := a.fortigateLiveContext(w, r, req.AttachFortigateIP)
		if !ok {
			return nil, false
		}
		add(block)
	}
	if req.AttachTopFlows || len(req.AttachFlowKeys) > 0 {
		var keys []obsstore.FlowKey
		if len(req.AttachFlowKeys) > 0 {
			if len(req.AttachFlowKeys) > 20 {
				writeErr(w, http.StatusBadRequest, "Troppi flussi selezionati: massimo 20 righe per analisi.")
				return nil, false
			}
			keys = make([]obsstore.FlowKey, len(req.AttachFlowKeys))
			for i, k := range req.AttachFlowKeys {
				keys[i] = obsstore.FlowKey{SrcIP: k.SrcIP, DstIP: k.DstIP, Protocol: k.Protocol, DstPort: k.DstPort}
			}
		}
		add(a.topFlowsContext(scoped, keys))
	}

	instructionBlocks := a.chatInstructionBlocks(req, claims.Role) // Task 3 (returns nil until then)

	if len(contextBlocks) == 0 && len(instructionBlocks) == 0 {
		return messages, true
	}
	budget := ai.ContextCharBudget(profile.Provider, profile.Model, profile.ContextBudgetChars)
	question := lastUserMessage(messages)
	contextBlocks = ai.FitContext(contextBlocks, budget, question)
	sys := ai.Message{Role: "system", Content: strings.Join(append(contextBlocks, instructionBlocks...), "\n\n")}
	return append([]ai.Message{sys}, messages...), true
}

func capStrings(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func lastUserMessage(messages []ai.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

// chatInstructionBlocks è un placeholder fino al Task 3.
func (a *App) chatInstructionBlocks(req *aiChatReq, role string) []string { return nil }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestChat' && go build ./...`
Expected: PASS (all TestChat*) + clean build.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_chat_handlers.go internal/api/ai_chat_handlers_test.go
git commit -m "feat(ai): chat context assembly + budget (2c-2 task 2)"
```

---

### Task 3: Config-proposal instruction block

**Files:**
- Modify: `internal/api/ai_chat_handlers.go`
- Test: `internal/api/ai_chat_handlers_test.go`

**Interfaces:**
- Consumes: `roleAtLeast`.
- Produces: the real body of `chatInstructionBlocks` (replaces the Task-2 placeholder).

- [ ] **Step 1: Write the failing test**

```go
func TestChatInstructionBlockOperatorOnly(t *testing.T) {
	app := chatApp(t)
	if err := app.store.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "cisco", Tenant: "acme", Site: "central"}); err != nil {
		t.Fatal(err)
	}
	var captured map[string]any
	srv := fakeOllama(t, "ok", &captured)
	seedOllamaProfile(t, app, srv.URL)

	body := `{"messages":[{"role":"user","content":"cambia la vlan"}],"attach_device_ips":["10.0.0.1"]}`

	sysContent := func(role string) string {
		captured = nil
		w := httptest.NewRecorder()
		app.handleAIChat(w, chatReq(body, role))
		if w.Code != 200 {
			t.Fatalf("%s: code=%d body=%s", role, w.Code, w.Body.String())
		}
		msgs, _ := captured["messages"].([]any)
		sys, _ := msgs[0].(map[string]any)
		return sys["content"].(string)
	}

	if !strings.Contains(sysContent("operator"), "sentinelnet-config") {
		t.Error("operator should get the config-proposal instruction block")
	}
	if strings.Contains(sysContent("viewer"), "sentinelnet-config") {
		t.Error("viewer must NOT get the config-proposal instruction block")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run TestChatInstructionBlockOperatorOnly`
Expected: FAIL — viewer and operator both lack the block (placeholder returns nil).

- [ ] **Step 3: Write minimal implementation**

Replace the placeholder `chatInstructionBlocks` with:

```go
// chatInstructionBlocks ritorna il contratto di proposta config (§10.2) quando
// sono allegate running-config di dispositivi e l'utente è operator+. Il
// modello PROPONE, non esegue: il browser mostra la proposta e solo dopo
// conferma esplicita chiama /api/bulk-command (blacklist/RBAC/audit invariati).
// Tenuto FUORI dal budget: non va mai troncato. Porta di instruction_blocks.
func (a *App) chatInstructionBlocks(req *aiChatReq, role string) []string {
	if len(req.AttachDeviceIPs) == 0 || !roleAtLeast(role, "operator") {
		return nil
	}
	return []string{
		"Se l'utente chiede una modifica di configurazione su uno dei " +
			"dispositivi allegati, oltre alla spiegazione emetti UN blocco " +
			"recintato cosi (JSON su una riga, device_ip tra quelli allegati):\n" +
			"```sentinelnet-config\n" +
			`{"device_ip": "<ip>", "commands": ["<riga config>", "..."], ` +
			`"config_mode": true, "save_after": false}` + "\n" +
			"```\n" +
			"Non usare il blocco per comandi show/diagnostici. Non proporre " +
			"comandi distruttivi (reload, erase, write erase, format).",
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestChat'`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_chat_handlers.go internal/api/ai_chat_handlers_test.go
git commit -m "feat(ai): config-proposal instruction block (2c-2 task 3)"
```

---

### Task 4: /api/ai/generate-config

**Files:**
- Modify: `internal/api/ai_chat_handlers.go`
- Modify: `internal/api/router.go`
- Test: `internal/api/ai_chat_handlers_test.go`

**Interfaces:**
- Consumes: `a.chatProfileAndKey`, `a.assertGroupAllowed`, `a.deviceRunningConfigContext`, `a.tenantCommonParameters`, `ai.ContextCharBudget`, `ai.FitContext`, `a.runChat`, `chatModelName`, `a.auditLog`, `claimsFrom`.
- Produces: `func (a *App) handleAIGenerateConfig(w http.ResponseWriter, r *http.Request)` + route.

- [ ] **Step 1: Write the failing test**

```go
func genReq(body, role string) *http.Request {
	req := httptest.NewRequest("POST", "/api/ai/generate-config", strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "u", Role: role}))
}

func TestGenerateConfigMissingFields(t *testing.T) {
	app := chatApp(t)
	srv := fakeOllama(t, "ok", nil)
	seedOllamaProfile(t, app, srv.URL)
	w := httptest.NewRecorder()
	app.handleAIGenerateConfig(w, genReq(`{"tenant":"","hostname":""}`, "admin"))
	if w.Code != 400 {
		t.Fatalf("missing fields: code=%d, want 400", w.Code)
	}
}

func TestGenerateConfigTemplatePath(t *testing.T) {
	app := chatApp(t)
	dir := t.TempDir()
	app.cfg = mkCfg(dir)
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(app.store.CreateTenant("acme", ""))
	must(app.store.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "cisco", Tenant: "acme", Site: "central"}))
	writeBackup(t, dir, "10.0.0.1", "hostname sw1\nntp server 10.0.0.250\n")
	var captured map[string]any
	srv := fakeOllama(t, "config generata", &captured)
	seedOllamaProfile(t, app, srv.URL)

	w := httptest.NewRecorder()
	app.handleAIGenerateConfig(w, genReq(`{"tenant":"acme","hostname":"sw-new","template_ip":"10.0.0.1"}`, "admin"))
	if w.Code != 200 {
		t.Fatalf("template path: code=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["reply"] != "config generata" {
		t.Errorf("unexpected reply: %+v", resp)
	}
	// User prompt should mention the new hostname.
	msgs, _ := captured["messages"].([]any)
	last, _ := msgs[len(msgs)-1].(map[string]any)
	if !strings.Contains(last["content"].(string), "sw-new") {
		t.Errorf("user prompt missing hostname: %+v", last)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ -run 'TestGenerateConfig'`
Expected: FAIL — `handleAIGenerateConfig` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `internal/api/ai_chat_handlers.go`:

```go
// handleAIGenerateConfig: POST /api/ai/generate-config (utente autenticato).
// Genera la config di un NUOVO switch del tenant da un template o dai parametri
// comuni dell'ambiente. Porta di ai_generate_config.
func (a *App) handleAIGenerateConfig(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	profile, apiKey, ok := a.chatProfileAndKey(w)
	if !ok {
		return
	}
	var req aiGenerateConfigReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	tenant := strings.TrimSpace(req.Tenant)
	hostname := strings.TrimSpace(req.Hostname)
	if tenant == "" || hostname == "" {
		writeErr(w, http.StatusBadRequest, "Tenant e hostname sono obbligatori.")
		return
	}
	if !a.assertGroupAllowed(w, r, tenant) {
		return
	}

	var context, source string
	if req.TemplateIP != "" {
		block, ok := a.deviceRunningConfigContext(w, r, req.TemplateIP)
		if !ok {
			return
		}
		context = block
		source = "la running-config del dispositivo template " + req.TemplateIP
	} else {
		block, ok := a.tenantCommonParameters(w, r, tenant)
		if !ok {
			return
		}
		context = block
		source = "i parametri comuni dell'ambiente del tenant"
	}

	requestLines := []string{"- hostname: " + hostname}
	if mgmt := strings.TrimSpace(req.MgmtIP); mgmt != "" {
		requestLines = append(requestLines, "- IP di management: "+mgmt)
	}
	if notes := strings.TrimSpace(req.Notes); notes != "" {
		if len(notes) > 1000 {
			notes = notes[:1000]
		}
		requestLines = append(requestLines, "- note aggiuntive: "+notes)
	}
	question := "Genera la configurazione completa proposta per un NUOVO switch del tenant '" + tenant +
		"', basandoti su " + source + ". Dati del nuovo switch:\n" + strings.Join(requestLines, "\n") + "\n" +
		"Riusa i parametri d'ambiente comuni (VLAN, VTP, NTP, syslog, AAA, DNS, SNMP, subnet di management) " +
		"adattandoli al nuovo dispositivo. Rispondi con UN solo blocco di codice contenente la configurazione " +
		"completa, seguito da brevi note sulle scelte fatte. Non inventare credenziali: usa segnaposto espliciti."

	budget := ai.ContextCharBudget(profile.Provider, profile.Model, profile.ContextBudgetChars)
	blocks := ai.FitContext([]string{context}, budget, question)
	messages := []ai.Message{
		{Role: "system", Content: strings.Join(blocks, "\n\n")},
		{Role: "user", Content: question},
	}
	reply, ok := a.runChat(w, profile, apiKey, messages)
	if !ok {
		return
	}
	a.auditLog("Config nuovo switch '" + hostname + "' (tenant '" + tenant + "') generata via AI dall'utente '" + claims.Username + "'.")
	writeJSON(w, http.StatusOK, map[string]any{
		"reply": reply, "provider": profile.Provider,
		"model": chatModelName(profile), "profile_name": profile.Name,
	})
}
```

Register route in `router.go`:

```go
	r.Post("/api/ai/generate-config", a.requireAuth("", a.handleAIGenerateConfig))
```

Note: the `notes[:1000]` byte-slice matches Python's `notes[:1000]`; keep as-is (Python also slices by codepoint but notes are free text — if the reviewer flags UTF-8, switching to a rune cut is acceptable, but the brief keeps parity with the byte slice; not required).

- [ ] **Step 4: Run test to verify it passes and the full package builds**

Run: `cd /c/Users/vidhi/dev_ved/sentinelnet-go && go test ./internal/api/ && go build ./... && go vet ./internal/api/`
Expected: PASS (whole api package) + clean build/vet.

- [ ] **Step 5: Commit**

```bash
git add internal/api/ai_chat_handlers.go internal/api/router.go internal/api/ai_chat_handlers_test.go
git commit -m "feat(ai): /api/ai/generate-config (2c-2 task 4)"
```

---

## Self-Review Notes

- **Spec coverage:** pipeline core+profile+errors (T1), context assembly+budget+flow-keys cap (T2), config-proposal instruction gated on operator+ (T3), generate-config with template/common-params paths (T4). Both endpoints + all attach flags + error mapping mapped.
- **Type consistency:** `activeProfile`/`chatProfileAndKey`/`runChat`/`chatModelName`/`chatInstructionBlocks`/`assembleChatContext` signatures are stable across tasks. `chatInstructionBlocks` is introduced as a placeholder in T2 and filled in T3 (same signature). `RateLimitRPM: &profile.RateLimitRPM` throughout.
- **Error contract:** every fallible builder call checks `ok` and returns immediately (builder already wrote). `runChat` maps 429/502. No double-write: the success path writes once at the end.
- **Redaction:** all model traffic goes through `ai.Chat`, which applies the redaction choke-point — the handlers never call provider senders directly.
- **Import staging:** T1 imports `errors`/`net/http`/`strings`/`ai` only. T2 adds the `obsstore` import (first real use in `assembleChatContext`). This avoids an unused-import error at the T1 boundary.
```
