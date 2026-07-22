// Package mcp: client per server MCP ESTERNI via Streamable HTTP (JSON-RPC 2.0).
// Porta di ai/mcp_client.py.
package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	mcpTimeout         = 30 * time.Second
	mcpProtocolVersion = "2025-06-18"
	mcpMaxRespBytes    = 5 * 1024 * 1024 // 5 MB cap
)

type ExternalClient struct {
	URL       string
	AuthToken string
	httpc     *http.Client
}

func NewExternalClient(url, authToken string) *ExternalClient {
	return &ExternalClient{
		URL:       strings.TrimRight(url, "/"),
		AuthToken: strings.TrimSpace(authToken),
		httpc:     &http.Client{Timeout: mcpTimeout},
	}
}

func ParseSSELastData(text string) string {
	var events []string
	var current []string
	lines := strings.Split(text, "\n")
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			if len(current) > 0 {
				events = append(events, strings.Join(current, "\n"))
				current = nil
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue // comment
		}
		if strings.HasPrefix(line, "data:") {
			val := strings.TrimLeft(line[5:], " ")
			current = append(current, val)
		}
	}
	if len(current) > 0 {
		events = append(events, strings.Join(current, "\n"))
	}
	if len(events) > 0 {
		return events[len(events)-1]
	}
	return ""
}

func readCappedBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	lr := io.LimitReader(resp.Body, maxBytes+1)
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("errore lettura risposta MCP: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("risposta del server MCP troppo grande (> %d byte)", maxBytes)
	}
	return body, nil
}

func (c *ExternalClient) parseResponse(resp *http.Response) (map[string]any, error) {
	ctype := strings.ToLower(resp.Header.Get("Content-Type"))
	body, err := readCappedBody(resp, mcpMaxRespBytes)
	if err != nil {
		return nil, err
	}

	payloadStr := string(body)
	if strings.Contains(ctype, "text/event-stream") {
		payloadStr = ParseSSELastData(payloadStr)
		if payloadStr == "" {
			return nil, fmt.Errorf("risposta SSE senza righe 'data:'")
		}
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(payloadStr), &data); err != nil {
		return nil, fmt.Errorf("risposta non è JSON valido: %w", err)
	}
	return data, nil
}

func (c *ExternalClient) rpc(url string, headers map[string]string, method string, params any, reqID int) (map[string]any, *http.Response, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  method,
		"params":  params,
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("errore di rete verso il server MCP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := readCappedBody(resp, 300)
		return nil, resp, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	data, err := c.parseResponse(resp)
	if err != nil {
		return nil, resp, err
	}

	if errObj, ok := data["error"].(map[string]any); ok && errObj != nil {
		return nil, resp, fmt.Errorf("errore JSON-RPC %v: %v", errObj["code"], errObj["message"])
	}
	return data, resp, nil
}

func (c *ExternalClient) openSession() (map[string]string, error) {
	headers := map[string]string{
		"Content-Type": "application/json",
		"Accept":       "application/json, text/event-stream",
	}
	if c.AuthToken != "" {
		headers["Authorization"] = "Bearer " + c.AuthToken
	}

	initParams := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":     map[string]any{},
		"clientInfo":       map[string]any{"name": "SentinelNet", "version": "preview"},
	}

	_, resp, err := c.rpc(c.URL, headers, "initialize", initParams, 1)
	if err != nil {
		return nil, err
	}

	sessionID := resp.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		sessionID = resp.Header.Get("mcp-session-id")
	}
	if sessionID != "" {
		headers["Mcp-Session-Id"] = sessionID
	}

	// Best effort notification
	notifPayload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	req, err := http.NewRequest(http.MethodPost, c.URL, bytes.NewReader(notifPayload))
	if err == nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		_, _ = c.httpc.Do(req)
	}

	return headers, nil
}

func (c *ExternalClient) ListTools() ([]any, error) {
	headers, err := c.openSession()
	if err != nil {
		return nil, err
	}
	data, _, err := c.rpc(c.URL, headers, "tools/list", map[string]any{}, 2)
	if err != nil {
		return nil, err
	}
	res, ok := data["result"].(map[string]any)
	if !ok {
		return []any{}, nil
	}
	tools, ok := res["tools"].([]any)
	if !ok {
		return []any{}, nil
	}
	return tools, nil
}

func (c *ExternalClient) CallTool(name string, arguments map[string]any) (any, error) {
	headers, err := c.openSession()
	if err != nil {
		return nil, err
	}
	if arguments == nil {
		arguments = map[string]any{}
	}
	data, _, err := c.rpc(c.URL, headers, "tools/call", map[string]any{"name": name, "arguments": arguments}, 3)
	if err != nil {
		return nil, err
	}
	res, ok := data["result"]
	if !ok {
		return map[string]any{}, nil
	}
	return res, nil
}
