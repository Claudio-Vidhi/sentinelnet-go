package observability

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/driver"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fortigate"
)

// maxSummary limita ogni snapshot: le osservazioni finiscono nel contesto
// dell'assistente AI, dove un dump di interfacce di mezzo megabyte lo
// saturerebbe da solo.
const maxSummary = 20_000

// ClientFunc costruisce il client REST per un IP. È iniettata perché i token
// sono cifrati nel vault, che vive nel package api: l'osservabilità non deve
// conoscere le credenziali, solo sapere come ottenere un client.
// Ritorna un errore quando il device non ha un target configurato.
type ClientFunc func(ip string) (*fortigate.Client, error)

// SetClientFunc abilita il poller REST. Senza, il poller resta inerte.
func (m *Manager) SetClientFunc(f ClientFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientFor = f
}

// PollOnce esegue un giro di polling sui FortiGate con un target REST
// configurato e accoda gli snapshot in api_observations. Ritorna il numero di
// snapshot accodati.
//
// Best-effort per device e per kind: un apparato spento o un token scaduto
// non devono impedire di raccogliere gli altri.
func (m *Manager) PollOnce(ctx context.Context) int {
	m.mu.Lock()
	clientFor := m.clientFor
	m.mu.Unlock()
	if clientFor == nil {
		return 0
	}

	devices, err := m.st.ListDevices()
	if err != nil {
		log.Printf("observability: poller API, lettura inventario fallita: %v", err)
		return 0
	}

	ts := time.Now().Unix()
	n := 0
	for _, d := range devices {
		if !driver.IsFortinet(d.Vendor) {
			continue
		}
		c, err := clientFor(d.IP)
		if err != nil || c == nil {
			continue // nessun target REST: non è un errore, è la norma
		}
		tenant := d.Tenant
		if tenant == "" {
			tenant = "Generale"
		}
		for _, snap := range pollDevice(ctx, c) {
			if m.obs.EnqueueWrite(
				`INSERT INTO api_observations(ts, tenant, device_ip, kind, summary_json)
				 VALUES (?, ?, ?, ?, ?)`,
				ts, tenant, d.IP, snap.kind, snap.summary) {
				n++
			}
		}
	}
	return n
}

type snapshot struct{ kind, summary string }

// pollDevice raccoglie gli snapshot di un singolo apparato.
//
// Solo REST, senza ripiego SSH: il poller gira in sottofondo su tutto
// l'inventario, e un ripiego SSH trasformerebbe ogni apparato irraggiungibile
// in decine di secondi di attesa per il giro intero. Le viste interattive
// hanno il loro ripiego; qui l'assenza di uno snapshot è accettabile.
func pollDevice(ctx context.Context, c *fortigate.Client) []snapshot {
	getters := []struct {
		kind string
		fn   func() (fortigate.Result, error)
	}{
		{"system_status", func() (fortigate.Result, error) { return c.SystemStatus(ctx, nil) }},
		{"interfaces", func() (fortigate.Result, error) { return c.Interfaces(ctx, nil) }},
	}

	out := make([]snapshot, 0, len(getters))
	for _, g := range getters {
		res, err := g.fn()
		if err != nil {
			continue
		}
		raw, err := json.Marshal(res.Data)
		if err != nil {
			continue
		}
		summary := string(raw)
		if len(summary) > maxSummary {
			summary = summary[:maxSummary]
		}
		out = append(out, snapshot{g.kind, summary})
	}
	return out
}

// apiPollLoop interroga i FortiGate ogni APIPollS secondi. L'intervallo è
// riletto a ogni giro, così cambiarlo da UI ha effetto senza riavvio.
func (m *Manager) apiPollLoop(ctx context.Context) {
	defer m.tasksWG.Done()
	for {
		interval := time.Duration(m.Config().APIPollS) * time.Second
		if interval <= 0 {
			interval = time.Duration(DefaultConfig().APIPollS) * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			if n := m.PollOnce(ctx); n > 0 {
				log.Printf("observability: poller API, %d snapshot accodati", n)
			}
		}
	}
}
