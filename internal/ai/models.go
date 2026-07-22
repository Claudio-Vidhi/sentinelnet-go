package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// defaultModels: modello di default per provider quando il profilo non ne
// imposta uno. DIVERGENZA §13: anthropic aggiornato a claude-sonnet-5 (il
// Python aveva claude-3-5-sonnet-latest, alias datato). Non esportato: non fa
// parte dell'API pubblica del package, l'accessor è GetDefaultModel.
var defaultModels = map[string]string{
	"anthropic": "claude-sonnet-5",
	"openai":    "gpt-4o-mini",
	"gemini":    "gemini-3-flash",
	"ollama":    "llama3",
}

// GetDefaultModel: default per il provider (minuscolo), "" se ignoto.
func GetDefaultModel(provider string) string {
	return defaultModels[strings.ToLower(strings.TrimSpace(provider))]
}

// normalizeGeminiModel toglie i prefissi "models/" ripetuti (evita
// "models/models/..."). "" -> default gemini.
func normalizeGeminiModel(model string) string {
	name := strings.TrimSpace(model)
	if name == "" {
		name = defaultModels["gemini"]
	}
	for strings.HasPrefix(name, "models/") {
		name = name[len("models/"):]
	}
	return name
}

// openaiNonChatHints: sottostringhe di modelli OpenAI non chat-capable.
var openaiNonChatHints = []string{
	"embedding", "whisper", "tts", "dall-e", "moderation", "davinci-002",
	"babbage-002", "text-", "audio", "realtime", "transcribe", "image",
}

func isOpenAINonChat(id string) bool {
	low := strings.ToLower(id)
	for _, h := range openaiNonChatHints {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// Endpoint fissi per il list-models, esposti come var per permettere agli
// httptest di reindirizzarli (stesso pattern di providers.go). Anthropic e
// Gemini ignorano baseURL (porta di _list_models_anthropic/_list_models_gemini,
// che non accettano base_url).
var (
	geminiModelsEndpointFmt = "https://generativelanguage.googleapis.com/v1beta/models?key=%s"
	anthropicModelsEndpoint = "https://api.anthropic.com/v1/models"
)

// defaultListModelsTimeout: porta di DEFAULT_TIMEOUT usato da list_models.
const defaultListModelsTimeout = 60 * time.Second

// getJSON esegue una GET e ritorna il body grezzo + status code. Porta dello
// schema requests.get(...) usato dai vari _list_models_*.
func getJSON(url string, headers map[string]string, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
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

// listModelsGemini: porta di _list_models_gemini. Ignora baseURL (endpoint
// fisso, come in Python).
func listModelsGemini(apiKey string, timeout time.Duration) ([]string, error) {
	if apiKey == "" {
		return nil, &Error{Msg: "API key Gemini mancante."}
	}
	url := fmt.Sprintf(geminiModelsEndpointFmt, apiKey)
	body, status, err := getJSON(url, nil, timeout)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, &Error{Msg: fmt.Sprintf("Gemini API error %d: %s", status, truncateRunes(string(body), 500))}
	}
	var data struct {
		Models []struct {
			Name                       string   `json:"name"`
			SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	models := []string{}
	for _, m := range data.Models {
		has := false
		for _, meth := range m.SupportedGenerationMethods {
			if meth == "generateContent" {
				has = true
				break
			}
		}
		if !has {
			continue
		}
		name := normalizeGeminiModel(m.Name)
		if name != "" {
			models = append(models, name)
		}
	}
	return models, nil
}

// listModelsOpenAI: porta di _list_models_openai. Onora baseURL. Ritorna
// ordinato ascendente (sorted() in Python).
func listModelsOpenAI(apiKey, baseURL string, timeout time.Duration) ([]string, error) {
	if apiKey == "" {
		return nil, &Error{Msg: "API key OpenAI mancante."}
	}
	base := baseURL
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	url := strings.TrimRight(base, "/") + "/models"
	headers := map[string]string{"Authorization": "Bearer " + apiKey}
	body, status, err := getJSON(url, headers, timeout)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, &Error{Msg: fmt.Sprintf("OpenAI API error %d: %s", status, truncateRunes(string(body), 500))}
	}
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	models := []string{}
	for _, m := range data.Data {
		if m.ID == "" {
			continue
		}
		if isOpenAINonChat(m.ID) {
			continue
		}
		models = append(models, m.ID)
	}
	sort.Strings(models)
	return models, nil
}

// listModelsAnthropic: porta di _list_models_anthropic. Ignora baseURL
// (endpoint fisso, come in Python).
func listModelsAnthropic(apiKey string, timeout time.Duration) ([]string, error) {
	if apiKey == "" {
		return nil, &Error{Msg: "API key Anthropic mancante."}
	}
	headers := map[string]string{"x-api-key": apiKey, "anthropic-version": "2023-06-01"}
	body, status, err := getJSON(anthropicModelsEndpoint, headers, timeout)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, &Error{Msg: fmt.Sprintf("Anthropic API error %d: %s", status, truncateRunes(string(body), 500))}
	}
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	models := []string{}
	for _, m := range data.Data {
		if m.ID != "" {
			models = append(models, m.ID)
		}
	}
	return models, nil
}

// listModelsOllama: porta di _list_models_ollama. Onora baseURL. Non
// richiede api_key.
func listModelsOllama(baseURL string, timeout time.Duration) ([]string, error) {
	base := baseURL
	if base == "" {
		base = "http://localhost:11434"
	}
	url := strings.TrimRight(base, "/") + "/api/tags"
	body, status, err := getJSON(url, nil, timeout)
	if err != nil {
		return nil, err
	}
	if status >= 400 {
		return nil, &Error{Msg: fmt.Sprintf("Ollama endpoint error %d: %s", status, truncateRunes(string(body), 500))}
	}
	var data struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	models := []string{}
	for _, m := range data.Models {
		if m.Name != "" {
			models = append(models, m.Name)
		}
	}
	return models, nil
}

// ListModels: porta di list_models. Dispatcha al lister del provider
// (minuscolo, trimmato); provider ignoto -> *Error. Errori dei singoli
// lister che sono già *Error passano invariati; qualunque altro errore
// (di rete/trasporto) viene incapsulato come Python fa con
// requests.RequestException.
func ListModels(provider, apiKey, baseURL string) ([]string, error) {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch p {
	case "gemini", "openai", "anthropic", "ollama":
	default:
		return nil, &Error{Msg: fmt.Sprintf("Provider non supportato: '%s'.", p)}
	}

	var models []string
	var err error
	switch p {
	case "gemini":
		models, err = listModelsGemini(apiKey, defaultListModelsTimeout)
	case "openai":
		models, err = listModelsOpenAI(apiKey, baseURL, defaultListModelsTimeout)
	case "anthropic":
		models, err = listModelsAnthropic(apiKey, defaultListModelsTimeout)
	case "ollama":
		models, err = listModelsOllama(baseURL, defaultListModelsTimeout)
	}
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, err
		}
		return nil, &Error{Msg: fmt.Sprintf("Errore di rete verso il provider '%s': %s", p, err)}
	}
	return models, nil
}
