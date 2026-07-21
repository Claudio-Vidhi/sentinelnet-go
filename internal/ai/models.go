package ai

import "strings"

// DefaultModels: modello di default per provider quando il profilo non ne
// imposta uno. DIVERGENZA §13: anthropic aggiornato a claude-sonnet-5 (il
// Python aveva claude-3-5-sonnet-latest, alias datato).
var DefaultModels = map[string]string{
	"anthropic": "claude-sonnet-5",
	"openai":    "gpt-4o-mini",
	"gemini":    "gemini-3-flash",
	"ollama":    "llama3",
}

// GetDefaultModel: default per il provider (minuscolo), "" se ignoto.
func GetDefaultModel(provider string) string {
	return DefaultModels[strings.ToLower(strings.TrimSpace(provider))]
}

// normalizeGeminiModel toglie i prefissi "models/" ripetuti (evita
// "models/models/..."). "" -> default gemini.
func normalizeGeminiModel(model string) string {
	name := strings.TrimSpace(model)
	if name == "" {
		name = DefaultModels["gemini"]
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
