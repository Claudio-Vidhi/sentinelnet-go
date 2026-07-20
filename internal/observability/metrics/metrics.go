// Package metrics: registro metriche in-process della pipeline di
// osservabilità. Contatori e gauge semplici, thread-safe, senza dipendenze
// esterne. Porta di observability/metrics.py.
//
// Lo snapshot è esposto da GET /api/observability/health (solo admin).
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// WarnInterval: al massimo un log di WARN per chiave in questo intervallo,
// per non inondare i log a ogni pacchetto scartato.
const WarnInterval = 60 * time.Second

// Registry è il registro delle metriche. Lo zero value non è utilizzabile:
// usare New.
type Registry struct {
	mu       sync.Mutex
	counters map[string]int64
	gauges   map[string]any
	warnLast map[string]time.Time
	// now è iniettabile nei test per non dipendere dall'orologio reale.
	now func() time.Time
}

func New() *Registry {
	return &Registry{
		counters: map[string]int64{},
		gauges:   map[string]any{},
		warnLast: map[string]time.Time{},
		now:      time.Now,
	}
}

// Inc incrementa un contatore di 1.
func (r *Registry) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }

// Add incrementa un contatore della quantità indicata.
func (r *Registry) Add(name string, amount int64, labels ...string) {
	k := key(name, labels)
	r.mu.Lock()
	r.counters[k] += amount
	r.mu.Unlock()
}

// SetGauge fissa il valore corrente di una gauge.
func (r *Registry) SetGauge(name string, value any, labels ...string) {
	k := key(name, labels)
	r.mu.Lock()
	r.gauges[k] = value
	r.mu.Unlock()
}

// ShouldWarn ritorna true se è passato WarnInterval dall'ultimo WARN per
// questa chiave.
func (r *Registry) ShouldWarn(k string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if last, ok := r.warnLast[k]; ok && now.Sub(last) < WarnInterval {
		return false
	}
	r.warnLast[k] = now
	return true
}

// Snapshot ritorna una copia di contatori e gauge.
func (r *Registry) Snapshot() (counters map[string]int64, gauges map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	counters = make(map[string]int64, len(r.counters))
	for k, v := range r.counters {
		counters[k] = v
	}
	gauges = make(map[string]any, len(r.gauges))
	for k, v := range r.gauges {
		gauges[k] = v
	}
	return counters, gauges
}

// key compone "nome{k=v,k=v}" con le label ordinate, come _key nel Python.
// labels è una sequenza piatta chiave/valore; un numero dispari di elementi
// fa ignorare l'ultimo.
func key(name string, labels []string) string {
	if len(labels) < 2 {
		return name
	}
	pairs := make([]string, 0, len(labels)/2)
	for i := 0; i+1 < len(labels); i += 2 {
		pairs = append(pairs, fmt.Sprintf("%s=%s", labels[i], labels[i+1]))
	}
	sort.Strings(pairs)
	return name + "{" + strings.Join(pairs, ",") + "}"
}
