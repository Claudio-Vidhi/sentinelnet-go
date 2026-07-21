package mcp

import (
	"bufio"
	"encoding/json"
	"io"
)

const (
	protocolVersion = "2025-06-18"
	maxText         = 200000
)

var serverInfo = map[string]any{"name": "sentinelnet", "version": "1.0.0"}

// Request è la richiesta REST che un tool costruisce dai suoi argomenti.
type Request struct {
	Method string
	Path   string
	Query  map[string]string
	Body   any
}

// Tool è un tool MCP come dato: descrizione e schema (contratto verso l'LLM) +
// il costruttore della richiesta REST (porta della lambda Python).
type Tool struct {
	Name         string
	Description  string
	InputSchema  map[string]any
	BuildRequest func(args map[string]any) Request
}

func reply(out io.Writer, id any, result, errObj any) {
	m := map[string]any{"jsonrpc": "2.0", "id": id}
	if errObj != nil {
		m["error"] = errObj
	} else {
		m["result"] = result
	}
	b, _ := json.Marshal(m)
	out.Write(append(b, '\n'))
}

func toolList(tools []Tool, disabled map[string]bool) map[string]any {
	list := []map[string]any{}
	for _, t := range tools {
		if disabled[t.Name] {
			continue
		}
		list = append(list, map[string]any{
			"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema,
		})
	}
	return map[string]any{"tools": list}
}

func toolCall(tools []Tool, call Caller, disabled map[string]bool, params map[string]any) map[string]any {
	name, _ := params["name"].(string)
	args, _ := params["arguments"].(map[string]any)
	if args == nil {
		args = map[string]any{}
	}
	var tool *Tool
	for i := range tools {
		if tools[i].Name == name {
			tool = &tools[i]
			break
		}
	}
	if tool == nil {
		return errText("Unknown tool: " + name)
	}
	if disabled[name] {
		return errText("Tool '" + name + "' disabled by the SentinelNet administrator.")
	}
	req := tool.BuildRequest(args)
	res, err := call.Call(req.Method, req.Path, req.Query, req.Body)
	if err != nil {
		return errText("Error: " + err.Error())
	}
	var text string
	if s, ok := res.(string); ok {
		text = s
	} else {
		b, _ := json.MarshalIndent(res, "", " ")
		text = string(b)
	}
	if len(text) > maxText {
		text = text[:maxText] + "\n... [truncated]"
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

func errText(msg string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true}
}

// serve è il loop JSON-RPC testabile: dipendenze iniettate.
func serve(in io.Reader, out io.Writer, tools []Tool, call Caller, disabled func() map[string]bool) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var msg map[string]any
		if json.Unmarshal(line, &msg) != nil {
			continue
		}
		method, _ := msg["method"].(string)
		id := msg["id"]
		switch method {
		case "initialize":
			pv := protocolVersion
			if p, ok := msg["params"].(map[string]any); ok {
				if v, ok := p["protocolVersion"].(string); ok && v != "" {
					pv = v
				}
			}
			reply(out, id, map[string]any{
				"protocolVersion": pv,
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      serverInfo,
			}, nil)
		case "notifications/initialized":
			// notifica: nessuna risposta
		case "ping":
			reply(out, id, map[string]any{}, nil)
		case "tools/list":
			reply(out, id, toolList(tools, disabled()), nil)
		case "tools/call":
			params, _ := msg["params"].(map[string]any)
			reply(out, id, toolCall(tools, call, disabled(), params), nil)
		default:
			if id != nil {
				reply(out, id, nil, map[string]any{"code": -32601, "message": "Method not found: " + method})
			}
		}
	}
}
