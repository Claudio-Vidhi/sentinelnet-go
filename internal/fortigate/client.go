// Package fortigate: accesso REST a un FortiGate (FortiOS API v2).
//
// Il trasporto primario è la REST API con token "api-user" e header
// Authorization Bearer; l'SSH resta un ripiego gestito altrove.
// Porta della parte di trasporto di services/fortigate_service.py.
package fortigate

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Error è un errore di comunicazione o autorizzazione verso il FortiGate.
// I messaggi sono mostrati in interfaccia e contengono il suggerimento
// diagnostico: vanno mantenuti così come sono.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, a ...any) *Error {
	return &Error{Msg: fmt.Sprintf(format, a...)}
}

// Client parla con un singolo FortiGate.
type Client struct {
	IP        string
	Port      int
	Token     string
	VerifyTLS bool
	// HTTP è iniettabile nei test; se nil viene costruito al primo uso.
	HTTP *http.Client
}

const (
	defaultTimeout = 30 * time.Second
	postTimeout    = 60 * time.Second
)

// New costruisce un client. Porta 0 significa 443.
func New(ip string, port int, token string, verifyTLS bool) *Client {
	if port == 0 {
		port = 443
	}
	return &Client{IP: ip, Port: port, Token: token, VerifyTLS: verifyTLS}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	c.HTTP = &http.Client{
		Transport: &http.Transport{
			// I FortiGate usano quasi sempre un certificato self-signed:
			// la verifica è opt-in per target, come nel Python.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: !c.VerifyTLS}, //nolint:gosec
		},
	}
	return c.HTTP
}

// Request esegue una chiamata su /api/v2/<path>.
func (c *Client) Request(ctx context.Context, method, path string,
	params map[string]string, body any, timeout time.Duration) (map[string]any, error) {

	if c.Token == "" {
		return nil, errf("Nessun token API configurato per %s.", c.IP)
	}
	if timeout == 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := fmt.Sprintf("https://%s:%d/api/v2/%s", c.IP, c.Port, strings.TrimPrefix(path, "/"))
	if len(params) > 0 {
		q := url.Values{}
		for k, v := range params {
			q.Set(k, v)
		}
		u += "?" + q.Encode()
	}

	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, errf("REST API %s: payload non serializzabile: %v", c.IP, err)
		}
		payload = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, payload)
	if err != nil {
		return nil, errf("REST API %s non raggiungibile: %v", c.IP, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		if isTLSTrustError(err) {
			return nil, errf(
				"REST API %s non raggiungibile: certificato TLS non attendibile (%v). "+
					"Il FortiGate usa probabilmente un certificato self-signed: disabilitare "+
					"'Verifica certificato TLS' nella configurazione del token oppure installare "+
					"un certificato attendibile sul FortiGate.", c.IP, err)
		}
		return nil, errf("REST API %s non raggiungibile: %v", c.IP, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, errf("REST API %s: token non valido o scaduto (401). "+
			"Verificare anche i trusted host dell'api-user.", c.IP)
	case resp.StatusCode == http.StatusForbidden:
		return nil, errf("REST API %s: accesso negato (403), profilo "+
			"accprofile dell'api-user insufficiente.", c.IP)
	case resp.StatusCode >= 400:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return nil, errf("REST API %s HTTP %d: %s", c.IP, resp.StatusCode, string(snippet))
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errf("REST API %s: lettura risposta fallita: %v", c.IP, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		// Alcuni endpoint (backup della config) rispondono con testo puro.
		return map[string]any{"raw": string(raw)}, nil
	}
	return out, nil
}

func (c *Client) Get(ctx context.Context, path string, params map[string]string) (map[string]any, error) {
	return c.Request(ctx, http.MethodGet, path, params, nil, defaultTimeout)
}

func (c *Client) Post(ctx context.Context, path string, body any, params map[string]string) (map[string]any, error) {
	return c.Request(ctx, http.MethodPost, path, params, body, postTimeout)
}

// GetCMDB interroga un endpoint cmdb con proiezione dei campi (format, es.
// "name|type|subnet") ed eventuale filtro. Riduce il payload, che su
// installazioni grandi sarebbe di svariati megabyte.
func (c *Client) GetCMDB(ctx context.Context, path, format, filter string) (map[string]any, error) {
	params := map[string]string{}
	if format != "" {
		params["format"] = format
	}
	if filter != "" {
		params["filter"] = filter
	}
	if len(params) == 0 {
		params = nil
	}
	return c.Get(ctx, path, params)
}

// TestResult è l'esito di una verifica di raggiungibilità.
type TestResult struct {
	OK      bool   `json:"ok"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

// TestConnection verifica il target con un timeout breve. Non ritorna mai un
// errore: l'esito negativo fa parte del risultato, perché la UI mostra lo
// stato di tutti i target insieme.
func (c *Client) TestConnection(ctx context.Context) TestResult {
	data, err := c.Request(ctx, http.MethodGet, "monitor/system/status", nil, nil, 5*time.Second)
	if err != nil {
		return TestResult{OK: false, Error: err.Error()}
	}
	return TestResult{OK: true, Version: strings.TrimPrefix(versionFrom(data), "v")}
}

// versionFrom cerca la versione in "results.version" e poi al livello
// superiore: la posizione cambia fra le versioni di FortiOS.
func versionFrom(data map[string]any) string {
	if results, ok := data["results"].(map[string]any); ok {
		if v, ok := results["version"].(string); ok && v != "" {
			return v
		}
	}
	if v, ok := data["version"].(string); ok {
		return v
	}
	return ""
}

// isTLSTrustError distingue il certificato non attendibile dagli altri errori
// di rete, per poter dare il suggerimento giusto.
func isTLSTrustError(err error) bool {
	var ce *tls.CertificateVerificationError
	if errors.As(err, &ce) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate")
}
