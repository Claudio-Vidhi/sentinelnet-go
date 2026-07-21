package ai

import (
	"fmt"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/redact"
)

type ChatOptions struct {
	Provider        string
	Model           string
	APIKey          string
	BaseURL         string
	Timeout         time.Duration
	RateLimitRPM    int
	AllowUnredacted bool
}

var validProviders = map[string]bool{"anthropic": true, "openai": true, "gemini": true, "ollama": true}

// Chat: unico punto d'uscita verso i provider. Redige ogni messaggio (I-1)
// salvo LLM locali autorizzati, applica il rate limit, poi dispatch. Porta di chat().
func Chat(msgs []Message, opts ChatOptions) (string, error) {
	if len(msgs) == 0 {
		return "", &Error{Msg: "Nessun messaggio da inviare."}
	}
	provider := strings.ToLower(strings.TrimSpace(opts.Provider))
	isLocal := provider == "ollama" || (provider == "openai" && IsLocalBaseURL(opts.BaseURL))
	if !(opts.AllowUnredacted && isLocal) {
		red := make([]Message, len(msgs))
		for i, m := range msgs {
			red[i] = Message{Role: m.Role, Content: redact.Text(m.Content)}
		}
		msgs = red
	}
	if !validProviders[provider] {
		return "", &Error{Msg: fmt.Sprintf("Provider non supportato: '%s'.", provider)}
	}
	if opts.RateLimitRPM != 0 {
		pkgRateLimiter.configure(opts.RateLimitRPM)
	}
	if ok, retry := pkgRateLimiter.allow(); !ok {
		return "", &RateLimitError{Msg: fmt.Sprintf(
			"Limite di %d richieste/minuto verso il provider AI superato. Riprova tra %.0fs.",
			pkgRateLimiter.currentRPM(), retry.Seconds())}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	switch provider {
	case "anthropic":
		return chatAnthropic(msgs, opts.Model, opts.APIKey, opts.BaseURL, timeout)
	case "openai":
		return chatOpenAI(msgs, opts.Model, opts.APIKey, opts.BaseURL, timeout)
	case "gemini":
		return chatGemini(msgs, opts.Model, opts.APIKey, opts.BaseURL, timeout)
	case "ollama":
		return chatOllama(msgs, opts.Model, opts.APIKey, opts.BaseURL, timeout)
	}
	return "", &Error{Msg: fmt.Sprintf("Provider non supportato: '%s'.", provider)}
}
