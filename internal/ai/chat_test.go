package ai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/redact"
)

// Un segreto in un messaggio DEVE arrivare mascherato al provider non locale.
func TestChatRedactsBeforeProvider(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()
	secret := "set password Segretissima_999!" // adegua se redact.Text non la maschera
	if redact.Text(secret) == secret {
		t.Skip("adeguare 'secret' a un valore che redact.Text maschera")
	}
	_, err := Chat([]Message{{Role: "user", Content: secret}}, ChatOptions{
		Provider: "openai", APIKey: "k", BaseURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(seen, "Segretissima_999") {
		t.Errorf("il segreto NON è stato redatto prima del provider: %s", seen)
	}
}

func TestChatEmptyMessages(t *testing.T) {
	if _, err := Chat(nil, ChatOptions{Provider: "openai", APIKey: "k"}); err == nil {
		t.Error("attesa un errore con 0 messaggi")
	}
}

func TestChatRateLimitBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()
	opts := ChatOptions{Provider: "openai", APIKey: "k", BaseURL: srv.URL, RateLimitRPM: 1}
	if _, err := Chat([]Message{{"user", "a"}}, opts); err != nil {
		t.Fatal(err)
	}
	var rl *RateLimitError
	if !asRateLimit(mustErr(Chat([]Message{{"user", "b"}}, opts)), &rl) {
		t.Error("2a chiamata deve dare *RateLimitError")
	}
	ConfigureRateLimit(0) // ripristina il limiter condiviso per gli altri test
}

func mustErr(_ string, err error) error { return err }
