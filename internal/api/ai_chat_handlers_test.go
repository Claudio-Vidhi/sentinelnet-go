package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
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
	tmpDir := t.TempDir()
	st, err := store.Open(filepath.Join(tmpDir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Addr:    ":8000",
		DataDir: tmpDir,
	}
	// Create backup directory
	if err := os.MkdirAll(cfg.BackupDir(), 0755); err != nil {
		t.Fatal(err)
	}
	return NewApp(cfg, st, nil, vault)
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

func TestChatInstructionBlockOperatorOnly(t *testing.T) {
	app := chatApp(t)
	if err := app.store.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "cisco", Tenant: "acme", Site: "central"}); err != nil {
		t.Fatal(err)
	}
	// Create a fake running-config backup file
	backupFile := filepath.Join(app.cfg.BackupDir(), "10.0.0.1.txt")
	if err := os.WriteFile(backupFile, []byte("interface Gi0/1\n ip address 10.0.0.1 255.255.255.0\n"), 0644); err != nil {
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
	userPrompt := last["content"].(string)
	if !strings.Contains(userPrompt, "sw-new") {
		t.Errorf("user prompt missing hostname: %+v", last)
	}
	// Regression guard: verify exact parity with Python source (segnaposto singular)
	if !strings.Contains(userPrompt, "usa segnaposto espliciti.") {
		t.Errorf("user prompt missing expected text 'usa segnaposto espliciti.': %s", userPrompt)
	}
}
