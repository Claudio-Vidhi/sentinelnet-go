package mcp

import (
	"sync"
	"time"
)

type toolConfig struct {
	call Caller
	mu   sync.Mutex
	at   time.Time
	set  map[string]bool
}

func newToolConfig(call Caller) *toolConfig {
	return &toolConfig{call: call, set: map[string]bool{}}
}

// disabled ritorna i tool disabilitati dall'admin, con cache TTL 60s. Su errore
// del centrale tiene l'ultimo set noto (come il Python).
func (t *toolConfig) disabled() map[string]bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.at.IsZero() && time.Since(t.at) < 60*time.Second {
		return t.set
	}
	res, err := t.call.Call("GET", "/api/mcp/tool-config", nil, nil)
	if err == nil {
		if m, ok := res.(map[string]any); ok {
			s := map[string]bool{}
			if arr, ok := m["disabled_tools"].([]any); ok {
				for _, v := range arr {
					if name, ok := v.(string); ok {
						s[name] = true
					}
				}
			}
			t.set = s
		}
	}
	t.at = time.Now()
	return t.set
}
