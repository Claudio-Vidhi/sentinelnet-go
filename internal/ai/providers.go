package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message è un turno di conversazione (role/content). Riusato da chat.go.
type Message struct {
	Role    string
	Content string
}

// Endpoint fissi, esposti come var per permettere agli httptest di
// reindirizzarli. Anthropic e Gemini ignorano baseURL (porta di
// _chat_anthropic/_chat_gemini, che non accettano base_url).
var (
	anthropicEndpoint = "https://api.anthropic.com/v1/messages"
	geminiEndpointFmt = "https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s"
)

// splitSystem separa gli eventuali messaggi "system" (concatenati con "\n\n")
// dal resto della conversazione. Porta di _split_system.
func splitSystem(msgs []Message) (system string, convo []Message) {
	var parts []string
	for _, m := range msgs {
		if m.Role == "system" {
			parts = append(parts, m.Content)
		} else {
			convo = append(convo, m)
		}
	}
	return strings.Join(parts, "\n\n"), convo
}

// providerHTTPError traduce un errore HTTP del provider in un errore
// leggibile. Porta di _raise_provider_http_error.
func providerHTTPError(label string, status int, body []byte) error {
	if status == 429 {
		return &RateLimitError{Msg: fmt.Sprintf(
			"Quota del provider %s superata (HTTP 429): limite di "+
				"richieste o di token/minuto raggiunto. Riduci il contesto allegato "+
				"(meno dispositivi/config, o abbassa il budget contesto nel profilo AI) "+
				"oppure riprova tra qualche minuto.", label)}
	}
	return &Error{Msg: fmt.Sprintf("%s API error %d: %s", label, status, truncateRunes(string(body), 500))}
}

// truncateRunes riproduce s[:limit] di Python (indicizzazione per code
// point, non per byte).
func truncateRunes(s string, limit int) string {
	r := []rune(s)
	if len(r) <= limit {
		return s
	}
	return string(r[:limit])
}

func postJSON(url string, headers map[string]string, payload any, timeout time.Duration) ([]byte, int, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, 0, err
	}
	// requests.post(url, json=payload) di Python imposta sempre
	// Content-Type: application/json; lo replichiamo come default prima di
	// applicare gli header specifici del provider.
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// chatAnthropic invia la conversazione ad Anthropic. Porta di _chat_anthropic.
// Ignora baseURL (endpoint fisso).
func chatAnthropic(msgs []Message, model, apiKey, baseURL string, timeout time.Duration) (string, error) {
	if apiKey == "" {
		return "", &Error{Msg: "API key Anthropic mancante."}
	}
	system, convo := splitSystem(msgs)
	m := model
	if m == "" {
		m = DefaultModels["anthropic"]
	}
	convoOut := make([]map[string]string, len(convo))
	for i, c := range convo {
		convoOut[i] = map[string]string{"role": c.Role, "content": c.Content}
	}
	payload := map[string]any{
		"model":      m,
		"max_tokens": 2048,
		"messages":   convoOut,
	}
	if system != "" {
		payload["system"] = system
	}
	headers := map[string]string{
		"x-api-key":         apiKey,
		"anthropic-version": "2023-06-01",
		"content-type":      "application/json",
	}
	body, status, err := postJSON(anthropicEndpoint, headers, payload, timeout)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", providerHTTPError("Anthropic", status, body)
	}
	var data struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, p := range data.Content {
		if p.Type == "text" {
			sb.WriteString(p.Text)
		}
	}
	return sb.String(), nil
}

// chatOpenAI invia la conversazione a OpenAI (o endpoint compatibile).
// Porta di _chat_openai. Onora baseURL.
func chatOpenAI(msgs []Message, model, apiKey, baseURL string, timeout time.Duration) (string, error) {
	if apiKey == "" {
		return "", &Error{Msg: "API key OpenAI mancante."}
	}
	base := baseURL
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	url := strings.TrimRight(base, "/") + "/chat/completions"
	msgsOut := make([]map[string]string, len(msgs))
	for i, m := range msgs {
		msgsOut[i] = map[string]string{"role": m.Role, "content": m.Content}
	}
	mdl := model
	if mdl == "" {
		mdl = DefaultModels["openai"]
	}
	payload := map[string]any{
		"model":    mdl,
		"messages": msgsOut,
	}
	headers := map[string]string{
		"Authorization": "Bearer " + apiKey,
		"Content-Type":  "application/json",
	}
	body, status, err := postJSON(url, headers, payload, timeout)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", providerHTTPError("OpenAI", status, body)
	}
	var data struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	if len(data.Choices) == 0 {
		return "", nil
	}
	return data.Choices[0].Message.Content, nil
}

var geminiRoleMap = map[string]string{"assistant": "model", "user": "user"}

// chatGemini invia la conversazione a Gemini. Porta di _chat_gemini. Ignora
// baseURL (endpoint fisso).
func chatGemini(msgs []Message, model, apiKey, baseURL string, timeout time.Duration) (string, error) {
	if apiKey == "" {
		return "", &Error{Msg: "API key Gemini mancante."}
	}
	system, convo := splitSystem(msgs)
	modelName := normalizeGeminiModel(model)
	url := fmt.Sprintf(geminiEndpointFmt, modelName, apiKey)

	contents := make([]map[string]any, len(convo))
	for i, m := range convo {
		role, ok := geminiRoleMap[m.Role]
		if !ok {
			role = "user"
		}
		contents[i] = map[string]any{
			"role":  role,
			"parts": []map[string]string{{"text": m.Content}},
		}
	}
	payload := map[string]any{"contents": contents}
	if system != "" {
		payload["systemInstruction"] = map[string]any{
			"parts": []map[string]string{{"text": system}},
		}
	}
	body, status, err := postJSON(url, nil, payload, timeout)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", providerHTTPError("Gemini", status, body)
	}
	var data struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	if len(data.Candidates) == 0 {
		return "", nil
	}
	var sb strings.Builder
	for _, p := range data.Candidates[0].Content.Parts {
		sb.WriteString(p.Text)
	}
	return sb.String(), nil
}

// chatOllama invia la conversazione a un endpoint Ollama. Porta di
// _chat_ollama. Onora baseURL. Non richiede api_key.
func chatOllama(msgs []Message, model, apiKey, baseURL string, timeout time.Duration) (string, error) {
	base := baseURL
	if base == "" {
		base = "http://localhost:11434"
	}
	url := strings.TrimRight(base, "/") + "/api/chat"
	msgsOut := make([]map[string]string, len(msgs))
	for i, m := range msgs {
		msgsOut[i] = map[string]string{"role": m.Role, "content": m.Content}
	}
	mdl := model
	if mdl == "" {
		mdl = DefaultModels["ollama"]
	}
	payload := map[string]any{
		"model":    mdl,
		"messages": msgsOut,
		"stream":   false,
	}
	body, status, err := postJSON(url, nil, payload, timeout)
	if err != nil {
		return "", err
	}
	if status >= 400 {
		return "", providerHTTPError("Ollama", status, body)
	}
	var data struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	return data.Message.Content, nil
}
