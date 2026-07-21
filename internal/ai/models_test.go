package ai

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestGetDefaultModel(t *testing.T) {
	if GetDefaultModel("anthropic") != "claude-sonnet-5" {
		t.Errorf("anthropic default = %q, atteso claude-sonnet-5 (divergenza §13)", GetDefaultModel("anthropic"))
	}
	if GetDefaultModel("openai") != "gpt-4o-mini" {
		t.Errorf("openai default = %q", GetDefaultModel("openai"))
	}
	if GetDefaultModel("GEMINI") != "gemini-3-flash" {
		t.Errorf("gemini default (case-insensitive) = %q", GetDefaultModel("GEMINI"))
	}
	if GetDefaultModel("bogus") != "" {
		t.Errorf("provider ignoto deve dare \"\", ottenuto %q", GetDefaultModel("bogus"))
	}
}

func TestNormalizeGeminiModel(t *testing.T) {
	if got := normalizeGeminiModel("models/models/gemini-3-flash"); got != "gemini-3-flash" {
		t.Errorf("normalize = %q", got)
	}
	if got := normalizeGeminiModel(""); got != "gemini-3-flash" {
		t.Errorf("normalize(\"\") deve dare il default gemini, ottenuto %q", got)
	}
}

func TestIsOpenAINonChat(t *testing.T) {
	for _, id := range []string{"text-embedding-3-small", "whisper-1", "dall-e-3", "gpt-4o-transcribe"} {
		if !isOpenAINonChat(id) {
			t.Errorf("%q dovrebbe essere non-chat", id)
		}
	}
	if isOpenAINonChat("gpt-4o") {
		t.Error("gpt-4o è chat, non deve essere filtrato")
	}
}

func TestListModelsOpenAIFiltersAndSorts(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Write([]byte(`{"data":[{"id":"o1-mini"},{"id":"gpt-4o"},{"id":"text-embedding-3-small"}]}`))
	}))
	defer srv.Close()

	got, err := ListModels("openai", "sk-x", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gpt-4o", "o1-mini"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("models = %v, want %v (embedding filtered, sorted asc)", got, want)
	}
	if gotAuth != "Bearer sk-x" {
		t.Errorf("auth = %q", gotAuth)
	}
	if !strings.HasSuffix(gotPath, "/models") {
		t.Errorf("path = %q", gotPath)
	}
}

func TestListModelsOpenAIMissingAPIKey(t *testing.T) {
	var e *Error
	_, err := ListModels("openai", "", "http://ignored.example")
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if e.Msg != "API key OpenAI mancante." {
		t.Errorf("msg = %q", e.Msg)
	}
}

func TestListModelsOpenAIHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("invalid api key"))
	}))
	defer srv.Close()

	var e *Error
	_, err := ListModels("openai", "sk-x", srv.URL)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	want := "OpenAI API error 401: invalid api key"
	if e.Msg != want {
		t.Errorf("msg = %q, want %q", e.Msg, want)
	}
}

func TestListModelsOllamaReturnsNamesInOrder(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Write([]byte(`{"models":[{"name":"llama3"},{"name":"mistral"},{"name":""}]}`))
	}))
	defer srv.Close()

	got, err := ListModels("ollama", "", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"llama3", "mistral"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("models = %v, want %v (order preserved, no sort, empty name skipped)", got, want)
	}
	if gotPath != "/api/tags" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestListModelsOllamaHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("boom"))
	}))
	defer srv.Close()

	var e *Error
	_, err := ListModels("ollama", "", srv.URL)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	want := "Ollama endpoint error 500: boom"
	if e.Msg != want {
		t.Errorf("msg = %q, want %q", e.Msg, want)
	}
}

func TestListModelsGeminiFiltersGenerateContentAndStripsPrefix(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.URL.Query().Get("key")
		w.Write([]byte(`{"models":[
			{"name":"models/gemini-3-flash","supportedGenerationMethods":["generateContent"]},
			{"name":"models/embedding-001","supportedGenerationMethods":["embedContent"]}
		]}`))
	}))
	defer srv.Close()

	origFmt := geminiModelsEndpointFmt
	geminiModelsEndpointFmt = srv.URL + "/v1beta/models?key=%s"
	defer func() { geminiModelsEndpointFmt = origFmt }()

	got, err := ListModels("gemini", "gk-x", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gemini-3-flash"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("models = %v, want %v (only generateContent-capable, models/ stripped)", got, want)
	}
	if gotKey != "gk-x" {
		t.Errorf("key query param = %q", gotKey)
	}
}

func TestListModelsGeminiMissingAPIKey(t *testing.T) {
	var e *Error
	_, err := ListModels("gemini", "", "")
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if e.Msg != "API key Gemini mancante." {
		t.Errorf("msg = %q", e.Msg)
	}
}

func TestListModelsGeminiHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	origFmt := geminiModelsEndpointFmt
	geminiModelsEndpointFmt = srv.URL + "/v1beta/models?key=%s"
	defer func() { geminiModelsEndpointFmt = origFmt }()

	var e *Error
	_, err := ListModels("gemini", "gk-x", "")
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	want := "Gemini API error 403: forbidden"
	if e.Msg != want {
		t.Errorf("msg = %q, want %q", e.Msg, want)
	}
}

func TestListModelsAnthropicReturnsIDs(t *testing.T) {
	var gotAPIKey, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		w.Write([]byte(`{"data":[{"id":"claude-3-5-sonnet-latest"},{"id":"claude-3-opus-latest"},{"id":""}]}`))
	}))
	defer srv.Close()

	origEndpoint := anthropicModelsEndpoint
	anthropicModelsEndpoint = srv.URL
	defer func() { anthropicModelsEndpoint = origEndpoint }()

	got, err := ListModels("anthropic", "ak-x", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"claude-3-5-sonnet-latest", "claude-3-opus-latest"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("models = %v, want %v (order preserved, empty id skipped)", got, want)
	}
	if gotAPIKey != "ak-x" {
		t.Errorf("x-api-key = %q", gotAPIKey)
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("anthropic-version = %q", gotVersion)
	}
}

func TestListModelsAnthropicMissingAPIKey(t *testing.T) {
	var e *Error
	_, err := ListModels("anthropic", "", "")
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if e.Msg != "API key Anthropic mancante." {
		t.Errorf("msg = %q", e.Msg)
	}
}

func TestListModelsBogusProvider(t *testing.T) {
	var e *Error
	_, err := ListModels("bogus", "key", "")
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	want := "Provider non supportato: 'bogus'."
	if e.Msg != want {
		t.Errorf("msg = %q, want %q", e.Msg, want)
	}
}

func TestListModelsProviderCaseInsensitiveAndTrimmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"models":[{"name":"llama3"}]}`))
	}))
	defer srv.Close()

	got, err := ListModels("  OLLAMA  ", "", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"llama3"}) {
		t.Errorf("models = %v", got)
	}
}

func TestListModelsNetworkErrorWrapped(t *testing.T) {
	// Porta 0 collegato ad un server chiuso subito dopo: connessione rifiutata,
	// mappata su "Errore di rete verso il provider '<p>': <e>" (porta di
	// requests.RequestException in list_models).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	badURL := srv.URL
	srv.Close() // nessuno ascolta più su questo indirizzo

	var e *Error
	_, err := ListModels("openai", "sk-x", badURL)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if !strings.HasPrefix(e.Msg, "Errore di rete verso il provider 'openai':") {
		t.Errorf("msg = %q, want prefix %q", e.Msg, "Errore di rete verso il provider 'openai':")
	}
}
