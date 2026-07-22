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
