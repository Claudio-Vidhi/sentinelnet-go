package mcp

import (
	"bufio"
	"encoding/json"
	"strings"
	"testing"
)

type fakeCaller struct{ last Request }

func (f *fakeCaller) Call(method, path string, query map[string]string, body any) (any, error) {
	f.last = Request{method, path, query, body}
	return map[string]any{"echo": path}, nil
}

func runServe(t *testing.T, tools []Tool, call Caller, disabled map[string]bool, lines ...string) []map[string]any {
	t.Helper()
	in := strings.NewReader(strings.Join(lines, "\n") + "\n")
	var buf strings.Builder
	serve(in, &buf, tools, call, func() map[string]bool { return disabled })
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(buf.String()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("riga non JSON: %q", sc.Text())
		}
		out = append(out, m)
	}
	return out
}

func TestServeInitializeAndPing(t *testing.T) {
	out := runServe(t, nil, &fakeCaller{}, nil,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(out) != 2 {
		t.Fatalf("risposte = %d, attese 2 (la notifica non risponde)", len(out))
	}
	res := out[0]["result"].(map[string]any)
	if res["serverInfo"].(map[string]any)["name"] != "sentinelnet" {
		t.Errorf("serverInfo = %#v", res["serverInfo"])
	}
}

func TestServeToolsListHidesDisabled(t *testing.T) {
	tools := []Tool{
		{Name: "a", Description: "A", InputSchema: map[string]any{"type": "object"}},
		{Name: "b", Description: "B", InputSchema: map[string]any{"type": "object"}},
	}
	out := runServe(t, tools, &fakeCaller{}, map[string]bool{"b": true},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	list := out[0]["result"].(map[string]any)["tools"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["name"] != "a" {
		t.Errorf("tools/list = %#v (b è disabilitato)", list)
	}
}

func TestServeToolsCallBuildsRequestAndTruncates(t *testing.T) {
	fc := &fakeCaller{}
	tools := []Tool{{
		Name: "get_x", Description: "X", InputSchema: map[string]any{"type": "object"},
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/x/" + a["ip"].(string)}
		},
	}}
	out := runServe(t, tools, fc, nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_x","arguments":{"ip":"1.2.3.4"}}}`)
	if fc.last.Path != "/api/x/1.2.3.4" {
		t.Errorf("path costruito = %q", fc.last.Path)
	}
	content := out[0]["result"].(map[string]any)["content"].([]any)
	if content[0].(map[string]any)["type"] != "text" {
		t.Errorf("content = %#v", content)
	}
}

func TestServeUnknownMethod(t *testing.T) {
	out := runServe(t, nil, &fakeCaller{}, nil,
		`{"jsonrpc":"2.0","id":9,"method":"frobnicate"}`)
	if out[0]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Errorf("error = %#v, atteso -32601", out[0]["error"])
	}
}

func TestServeToolsCallDisabledIsError(t *testing.T) {
	tools := []Tool{{Name: "a", Description: "A", InputSchema: map[string]any{"type": "object"},
		BuildRequest: func(map[string]any) Request { return Request{Method: "GET", Path: "/api/a"} }}}
	out := runServe(t, tools, &fakeCaller{}, map[string]bool{"a": true},
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{}}}`)
	if out[0]["result"].(map[string]any)["isError"] != true {
		t.Errorf("un tool disabilitato deve dare isError: %#v", out[0]["result"])
	}
}

type longCaller struct{}

func (l *longCaller) Call(method, path string, query map[string]string, body any) (any, error) {
	return strings.Repeat("x", maxText+500), nil
}

func TestServeToolsCallTruncates(t *testing.T) {
	tools := []Tool{{
		Name:        "long_tool",
		Description: "Returns long string",
		InputSchema: map[string]any{"type": "object"},
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/long"}
		},
	}}

	out := runServe(t, tools, &longCaller{}, nil,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"long_tool","arguments":{}}}`)

	result := out[0]["result"].(map[string]any)
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)

	// Check exact length: should be maxText + truncation marker
	expectedLen := maxText + len("\n... [truncated]")
	if len(text) != expectedLen {
		t.Errorf("truncated text length = %d, expected %d", len(text), expectedLen)
	}

	// Check suffix
	if !strings.HasSuffix(text, "\n... [truncated]") {
		t.Errorf("text does not end with truncation marker: %q", text[len(text)-30:])
	}
}
