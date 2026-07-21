package mcp

import "testing"

type stubCaller struct {
	calls int
	names []string
	err   error
}

func (s *stubCaller) Call(method, path string, q map[string]string, b any) (any, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	arr := make([]any, len(s.names))
	for i, n := range s.names {
		arr[i] = n
	}
	return map[string]any{"disabled_tools": arr}, nil
}

// La cache TTL evita una HTTP per ogni chiamata: due letture ravvicinate = 1 poll.
func TestToolConfigCaches(t *testing.T) {
	sc := &stubCaller{names: []string{"get_anomalies"}}
	tc := newToolConfig(sc)
	d1 := tc.disabled()
	d2 := tc.disabled()
	if !d1["get_anomalies"] || !d2["get_anomalies"] {
		t.Errorf("disabled = %v / %v", d1, d2)
	}
	if sc.calls != 1 {
		t.Errorf("poll = %d, atteso 1 (cache)", sc.calls)
	}
}

// Su errore del centrale si tiene l'ultimo set noto (qui: vuoto), senza panico.
func TestToolConfigErrorKeepsLast(t *testing.T) {
	sc := &stubCaller{err: errBoom}
	tc := newToolConfig(sc)
	if d := tc.disabled(); len(d) != 0 {
		t.Errorf("disabled = %v, atteso vuoto su errore iniziale", d)
	}
}

var errBoom = &boom{}

type boom struct{}

func (b *boom) Error() string { return "boom" }
