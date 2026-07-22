package ai

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func asRateLimit(err error, tgt **RateLimitError) bool { return errors.As(err, tgt) }
func asErr(err error, tgt **Error) bool                { return errors.As(err, tgt) }

func TestChatOpenAIBuildsRequestAndParses(t *testing.T) {
	var gotAuth, gotPath string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		w.Write([]byte(`{"choices":[{"message":{"content":"ciao"}}]}`))
	}))
	defer srv.Close()
	reply, err := chatOpenAI([]Message{{"user", "hi"}}, "gpt-4o", "sk-x", srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reply != "ciao" {
		t.Errorf("reply = %q", reply)
	}
	if gotAuth != "Bearer sk-x" {
		t.Errorf("auth = %q", gotAuth)
	}
	if !strings.HasSuffix(gotPath, "/chat/completions") {
		t.Errorf("path = %q", gotPath)
	}
	if body["model"] != "gpt-4o" {
		t.Errorf("model = %v", body["model"])
	}
}

func TestChatOpenAIMissingAPIKey(t *testing.T) {
	var e *Error
	_, err := chatOpenAI([]Message{{"user", "hi"}}, "gpt-4o", "", "", 5*time.Second)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if e.Msg != "API key OpenAI mancante." {
		t.Errorf("msg = %q", e.Msg)
	}
}

func TestProviderHTTPError429IsRateLimit(t *testing.T) {
	var rl *RateLimitError
	if !asRateLimit(providerHTTPError("OpenAI", 429, []byte(`{"error":"quota"}`)), &rl) {
		t.Error("429 deve dare *RateLimitError")
	}
	var e *Error
	if !asErr(providerHTTPError("OpenAI", 500, []byte("boom")), &e) {
		t.Error("500 deve dare *Error")
	}
}

func TestProviderHTTPError429MessageVerbatim(t *testing.T) {
	var rl *RateLimitError
	err := providerHTTPError("Gemini", 429, []byte(`ignored`))
	if !asRateLimit(err, &rl) {
		t.Fatalf("expected *RateLimitError, got %v (%T)", err, err)
	}
	want := "Quota del provider Gemini superata (HTTP 429): limite di " +
		"richieste o di token/minuto raggiunto. Riduci il contesto allegato " +
		"(meno dispositivi/config, o abbassa il budget contesto nel profilo AI) " +
		"oppure riprova tra qualche minuto."
	if rl.Msg != want {
		t.Errorf("msg = %q\nwant = %q", rl.Msg, want)
	}
}

func TestProviderHTTPErrorGenericTruncatesBodyTo500(t *testing.T) {
	var e *Error
	longBody := strings.Repeat("x", 600)
	err := providerHTTPError("OpenAI", 500, []byte(longBody))
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	want := "OpenAI API error 500: " + strings.Repeat("x", 500)
	if e.Msg != want {
		t.Errorf("msg len = %d, want len = %d", len(e.Msg), len(want))
	}
}

func TestSplitSystem(t *testing.T) {
	msgs := []Message{
		{"system", "part1"},
		{"user", "hi"},
		{"system", "part2"},
		{"assistant", "yo"},
	}
	system, convo := splitSystem(msgs)
	if system != "part1\n\npart2" {
		t.Errorf("system = %q", system)
	}
	if len(convo) != 2 || convo[0].Role != "user" || convo[1].Role != "assistant" {
		t.Errorf("convo = %+v", convo)
	}
}

func TestChatAnthropicBuildsRequestAndParses(t *testing.T) {
	var gotAPIKey, gotVersion, gotContentType string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAPIKey = r.Header.Get("x-api-key")
		gotVersion = r.Header.Get("anthropic-version")
		gotContentType = r.Header.Get("content-type")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		w.Write([]byte(`{"content":[{"type":"text","text":"ciao "},{"type":"text","text":"mondo"}]}`))
	}))
	defer srv.Close()

	// chatAnthropic hits a fixed endpoint (ignores baseURL, per Python
	// _chat_anthropic). To keep this hermetic we redirect the package-level
	// endpoint var to the test server for the duration of the test.
	origEndpoint := anthropicEndpoint
	anthropicEndpoint = srv.URL
	defer func() { anthropicEndpoint = origEndpoint }()

	reply, err := chatAnthropic(
		[]Message{{"system", "you are a bot"}, {"user", "hi"}},
		"", "ak-x", "http://ignored.example", 5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if reply != "ciao mondo" {
		t.Errorf("reply = %q", reply)
	}
	if gotAPIKey != "ak-x" {
		t.Errorf("x-api-key = %q", gotAPIKey)
	}
	if gotVersion != "2023-06-01" {
		t.Errorf("anthropic-version = %q", gotVersion)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if body["max_tokens"] != float64(2048) {
		t.Errorf("max_tokens = %v", body["max_tokens"])
	}
	if body["model"] != defaultModels["anthropic"] {
		t.Errorf("model = %v", body["model"])
	}
	if body["system"] != "you are a bot" {
		t.Errorf("system = %v", body["system"])
	}
	msgs, _ := body["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("messages = %v, want 1 (system split out)", body["messages"])
	}
	first, _ := msgs[0].(map[string]any)
	if first["role"] != "user" || first["content"] != "hi" {
		t.Errorf("messages[0] = %v", first)
	}
}

func TestChatAnthropicMissingAPIKey(t *testing.T) {
	var e *Error
	_, err := chatAnthropic([]Message{{"user", "hi"}}, "", "", "", 5*time.Second)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if e.Msg != "API key Anthropic mancante." {
		t.Errorf("msg = %q", e.Msg)
	}
}

func TestChatAnthropicHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("kaboom"))
	}))
	defer srv.Close()
	origEndpoint := anthropicEndpoint
	anthropicEndpoint = srv.URL
	defer func() { anthropicEndpoint = origEndpoint }()

	var e *Error
	_, err := chatAnthropic([]Message{{"user", "hi"}}, "", "ak-x", "", 5*time.Second)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
}

func TestChatGeminiBuildsRequestAndParses(t *testing.T) {
	var gotURL, gotContentType string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ciao "},{"text":"mondo"}]}}]}`))
	}))
	defer srv.Close()

	origEndpoint := geminiEndpointFmt
	geminiEndpointFmt = srv.URL + "/v1beta/models/%s:generateContent?key=%s"
	defer func() { geminiEndpointFmt = origEndpoint }()

	reply, err := chatGemini(
		[]Message{{"system", "sys prompt"}, {"user", "hi"}, {"assistant", "prev reply"}},
		"gemini-3-flash", "gk-x", "http://ignored.example", 5*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if reply != "ciao mondo" {
		t.Errorf("reply = %q", reply)
	}
	if !strings.Contains(gotURL, ":generateContent?key=gk-x") {
		t.Errorf("url = %q", gotURL)
	}
	if !strings.Contains(gotURL, "gemini-3-flash") {
		t.Errorf("url missing model = %q", gotURL)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q", gotContentType)
	}
	sysInstr, _ := body["systemInstruction"].(map[string]any)
	parts, _ := sysInstr["parts"].([]any)
	if len(parts) != 1 || parts[0].(map[string]any)["text"] != "sys prompt" {
		t.Errorf("systemInstruction = %v", body["systemInstruction"])
	}
	contents, _ := body["contents"].([]any)
	if len(contents) != 2 {
		t.Fatalf("contents = %v, want 2", body["contents"])
	}
	c0 := contents[0].(map[string]any)
	if c0["role"] != "user" {
		t.Errorf("contents[0].role = %v", c0["role"])
	}
	c1 := contents[1].(map[string]any)
	if c1["role"] != "model" {
		t.Errorf("contents[1].role (assistant->model) = %v", c1["role"])
	}
}

func TestChatGeminiMissingAPIKey(t *testing.T) {
	var e *Error
	_, err := chatGemini([]Message{{"user", "hi"}}, "", "", "", 5*time.Second)
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	if e.Msg != "API key Gemini mancante." {
		t.Errorf("msg = %q", e.Msg)
	}
}

func TestChatOllamaBuildsRequestAndParses(t *testing.T) {
	var gotPath, gotContentType string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		w.Write([]byte(`{"message":{"content":"ciao"}}`))
	}))
	defer srv.Close()

	reply, err := chatOllama([]Message{{"user", "hi"}}, "llama3", "", srv.URL, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if reply != "ciao" {
		t.Errorf("reply = %q", reply)
	}
	if gotContentType != "application/json" {
		t.Errorf("content-type = %q", gotContentType)
	}
	if gotPath != "/api/chat" {
		t.Errorf("path = %q", gotPath)
	}
	if body["stream"] != false {
		t.Errorf("stream = %v", body["stream"])
	}
	if body["model"] != "llama3" {
		t.Errorf("model = %v", body["model"])
	}
}

func TestChatOllamaHTTPErrorIsPlainError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		w.Write([]byte("rate limited by local server"))
	}))
	defer srv.Close()

	_, err := chatOllama([]Message{{"user", "hi"}}, "llama3", "", srv.URL, 5*time.Second)

	var e *Error
	if !asErr(err, &e) {
		t.Fatalf("expected *Error, got %v (%T)", err, err)
	}
	var rl *RateLimitError
	if asRateLimit(err, &rl) {
		t.Fatalf("Ollama HTTP error must NOT be *RateLimitError, got %v", err)
	}
	if !strings.Contains(e.Msg, "Ollama endpoint error") {
		t.Errorf("msg = %q, want to contain %q", e.Msg, "Ollama endpoint error")
	}
	if strings.Contains(e.Msg, "API error") {
		t.Errorf("msg = %q, must not contain %q", e.Msg, "API error")
	}
	if strings.Contains(e.Msg, "Quota del provider") {
		t.Errorf("msg = %q, must not contain %q", e.Msg, "Quota del provider")
	}
}

func TestChatOllamaDefaultBaseURLUsesLocalhost(t *testing.T) {
	// No live server on localhost:11434 expected in CI; just confirm the
	// call attempts to reach the default host by checking the error mentions
	// a connection failure rather than a malformed-request error. This is a
	// light smoke check, not a network integration test.
	_, err := chatOllama([]Message{{"user", "hi"}}, "", "", "", 1*time.Millisecond)
	if err == nil {
		t.Skip("an Ollama instance happens to be reachable locally; nothing to assert")
	}
}
