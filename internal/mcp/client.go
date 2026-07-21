// Package mcp: server MCP (Model Context Protocol) su stdio. Ponte autenticato
// verso l'API REST del centrale — nessuna logica di autorizzazione qui.
package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/redact"
)

// Caller astrae la chiamata REST così il loop JSON-RPC è testabile con un fake.
type Caller interface {
	Call(method, path string, query map[string]string, body any) (any, error)
}

// Client è il ponte HTTP autenticato verso il centrale (porta di api() Python).
type Client struct {
	baseURL  string
	username string
	password string
	verify   bool
	httpc    *http.Client
	token    string
}

// NewClientFromEnv costruisce il client dalle variabili d'ambiente SENTINELNET_*.
func NewClientFromEnv() (*Client, error) {
	u := strings.TrimRight(getenv("SENTINELNET_URL", "http://127.0.0.1:8765"), "/")
	user := os.Getenv("SENTINELNET_USERNAME")
	pass := os.Getenv("SENTINELNET_PASSWORD")
	if user == "" || pass == "" {
		return nil, fmt.Errorf("SENTINELNET_USERNAME / SENTINELNET_PASSWORD non impostate")
	}
	verify := os.Getenv("SENTINELNET_VERIFY_TLS") != "0"
	hc := &http.Client{Timeout: 60 * time.Second}
	if !verify {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	return &Client{baseURL: u, username: user, password: pass, verify: verify, httpc: hc}, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// httpError costruisce l'errore per una risposta >=400, con lo stesso
// dettaglio del Python: campo JSON "detail" se presente, altrimenti il body
// grezzo (porta di raise_for_status / "detail" in api()).
func httpError(status int, raw []byte) error {
	detail := string(raw)
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		if d, ok := m["detail"].(string); ok {
			detail = d
		}
	}
	return fmt.Errorf("HTTP %d: %s", status, detail)
}

// loginTimeout è il timeout della sola richiesta di login (15s in Python,
// contro i 60s di api()).
const loginTimeout = 15 * time.Second

func (c *Client) login() error {
	body, _ := json.Marshal(map[string]string{"username": c.username, "password": c.password})
	ctx, cancel := context.WithTimeout(context.Background(), loginTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return httpError(resp.StatusCode, raw)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	c.token = out.AccessToken
	return nil
}

// Call esegue la richiesta REST col JWT; su 401 alla prima prova rifà login e
// riprova una volta. Il risultato passa per redact (finding I-1).
func (c *Client) Call(method, path string, query map[string]string, body any) (any, error) {
	if c.token == "" {
		if err := c.login(); err != nil {
			return nil, err
		}
	}
	var resp *http.Response
	for attempt := 1; attempt <= 2; attempt++ {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, c.baseURL+path, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if query != nil {
			q := req.URL.Query()
			for k, v := range query {
				q.Set(k, v)
			}
			req.URL.RawQuery = q.Encode()
		}
		resp, err = c.httpc.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == 401 && attempt == 1 {
			resp.Body.Close()
			if err := c.login(); err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, httpError(resp.StatusCode, raw)
	}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		return redact.Any(v), nil
	}
	return redact.Text(string(raw)), nil
}
