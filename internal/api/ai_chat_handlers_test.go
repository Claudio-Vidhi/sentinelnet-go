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
