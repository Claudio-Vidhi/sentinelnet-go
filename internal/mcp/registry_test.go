package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func normJSON(t *testing.T, b []byte) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("JSON non valido: %v", err)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return string(out)
}

// Il catalogo tool (nome/descrizione/schema) è il contratto verso l'LLM: deve
// combaciare byte-per-byte col tools/list del Python.
func TestToolsListMatchesPythonGolden(t *testing.T) {
	list := map[string]any{"tools": func() []map[string]any {
		out := []map[string]any{}
		for _, x := range Tools {
			out = append(out, map[string]any{
				"name": x.Name, "description": x.Description, "inputSchema": x.InputSchema,
			})
		}
		return out
	}()}
	got, _ := json.Marshal(list)
	want, err := os.ReadFile(filepath.Join("testdata", "tools_list.json"))
	if err != nil {
		t.Fatal(err)
	}
	if normJSON(t, got) != normJSON(t, want) {
		t.Errorf("tools/list diverso dal Python:\n--- Go ---\n%s", normJSON(t, got))
	}
}

// Il mapping argomenti->richiesta REST deve essere identico al Python.
func TestRequestMapMatchesPythonGolden(t *testing.T) {
	sample := map[string]any{
		"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "command": "show version",
		"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "dest": "8.8.8.8",
		"dest_port": float64(443), "count": float64(100), "hostname": "H1",
		"window": "15m", "limit": float64(20), "metric": "bytes", "status": "new",
		"group": "all", "vlan": "10", "interface": "Gi0/1", "switch": "10.0.0.2",
		"protocol": "TCP", "action": "accept",
	}
	got := map[string]any{}
	for _, x := range Tools {
		props, _ := x.InputSchema["properties"].(map[string]any)
		args := map[string]any{}
		for k := range props {
			if v, ok := sample[k]; ok {
				args[k] = v
			}
		}
		r := x.BuildRequest(args)
		var params any
		if r.Query != nil {
			pm := map[string]any{}
			for k, v := range r.Query {
				pm[k] = v
			}
			params = pm
		}
		got[x.Name] = map[string]any{"method": r.Method, "path": r.Path, "params": params, "body": r.Body}
	}
	gb, _ := json.Marshal(got)
	want, err := os.ReadFile(filepath.Join("testdata", "request_map.json"))
	if err != nil {
		t.Fatal(err)
	}
	if normJSON(t, gb) != normJSON(t, want) {
		t.Errorf("request map diverso dal Python:\n--- Go ---\n%s", normJSON(t, gb))
	}
}
