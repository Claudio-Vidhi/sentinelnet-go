package observability

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/ingest"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// retentionInterval: un ciclo di pruning all'ora.
const retentionInterval = time.Hour

// Manager applica una configurazione desiderata allo stato live: listener UDP
// e task periodici, senza mai richiedere il riavvio del processo.
type Manager struct {
	obs      *obsstore.Store
	st       *store.Store
	metrics  *metrics.Registry
	decoder  *ingest.Decoder
	deps     *ingest.Deps
	auditLog func(string)

	mu        sync.Mutex
	listeners map[string]*ingest.Listener
	current   map[string]bindKey
	status    map[string]ListenerStatus
	cfg       Config
	clientFor ClientFunc

	retentionOnce sync.Once
	cancelTasks   context.CancelFunc
	tasksWG       sync.WaitGroup
}

type bindKey struct {
	bind string
	port int
}

// NewManager costruisce il gestore. auditLog può essere nil.
func NewManager(obs *obsstore.Store, st *store.Store, auditLog func(string)) *Manager {
	m := &Manager{
		obs:       obs,
		st:        st,
		metrics:   obs.Metrics,
		decoder:   ingest.NewDecoder(),
		auditLog:  auditLog,
		listeners: map[string]*ingest.Listener{},
		current:   map[string]bindKey{},
		status:    map[string]ListenerStatus{},
		cfg:       DefaultConfig(),
	}
	m.deps = &ingest.Deps{
		Resolver: newStoreResolver(st),
		Sink:     storeSink{obs: obs},
		Metrics:  obs.Metrics,
		Audit:    auditLog,
	}
	return m
}

// Decoder è condiviso dai listener NetFlow/IPFIX ed è esposto per l'endpoint
// di health (dimensione della cache template).
func (m *Manager) Decoder() *ingest.Decoder { return m.decoder }

// Config ritorna l'ultima configurazione applicata.
func (m *Manager) Config() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

// Status ritorna lo stato corrente dei listener.
func (m *Manager) Status() map[string]ListenerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]ListenerStatus, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out
}

// listenerSpecs descrive i quattro protocolli supportati.
// NetFlow e IPFIX condividono lo stesso decoder, e quindi la stessa cache dei
// template: lo stesso exporter può inviare su entrambe le porte.
func (m *Manager) listenerSpecs(cfg Config) map[string]struct {
	lc     ListenerConfig
	decode ingest.DecodeFunc
	source string
} {
	flowDecode := func(source string) ingest.DecodeFunc {
		return func(data []byte, exporterIP string, receiveTS int64) ingest.Batch {
			recs, stats := m.decoder.Parse(data, exporterIP)
			return ingest.Batch{
				Flows:                     recs,
				ParseErrors:               stats.ParseErrors,
				DataBeforeTemplateDropped: stats.DataBeforeTemplateDropped,
			}
		}
	}
	sflowDecode := func(data []byte, exporterIP string, receiveTS int64) ingest.Batch {
		recs, skipped, ok := ingest.ParseSFlow(data, exporterIP, receiveTS)
		b := ingest.Batch{Flows: recs, CounterSamplesSkipped: skipped}
		if !ok {
			b.ParseErrors = 1
		}
		return b
	}
	syslogDecode := func(data []byte, exporterIP string, receiveTS int64) ingest.Batch {
		return ingest.Batch{Syslogs: ingest.ParseSyslog(data, exporterIP, time.Unix(receiveTS, 0))}
	}

	return map[string]struct {
		lc     ListenerConfig
		decode ingest.DecodeFunc
		source string
	}{
		"ipfix":   {cfg.IPFIX, flowDecode("ipfix"), "ipfix"},
		"netflow": {cfg.NetFlow, flowDecode("netflow"), "netflow"},
		"sflow":   {cfg.SFlow, sflowDecode, "sflow"},
		"syslog":  {cfg.Syslog, syslogDecode, ""},
	}
}

// Apply porta lo stato live alla configurazione desiderata. È idempotente:
// richiamabile al boot e a ogni salvataggio della configurazione.
func (m *Manager) Apply(ctx context.Context, cfg Config) {
	specs := m.listenerSpecs(cfg)

	m.mu.Lock()
	m.cfg = cfg

	// 1. Ferma i listener rimossi o con bind/porta cambiati.
	//    Lo stop precede sempre lo start: Windows non consente il doppio bind
	//    della stessa porta, quindi un rebind "start-then-stop" fallirebbe.
	var toStop []*ingest.Listener
	for name, l := range m.listeners {
		spec, wanted := specs[name]
		want := cfg.Enabled && wanted && spec.lc.Enabled
		key := bindKey{cfg.Bind, spec.lc.Port}
		if !want || m.current[name] != key {
			toStop = append(toStop, l)
			delete(m.listeners, name)
			delete(m.current, name)
			if !want {
				m.status[name] = ListenerStatus{Active: false}
			}
		}
	}
	m.mu.Unlock()

	for _, l := range toStop {
		l.Stop(ctx)
	}

	// 2. Avvia i listener mancanti.
	for name, spec := range specs {
		want := cfg.Enabled && spec.lc.Enabled
		m.mu.Lock()
		_, running := m.listeners[name]
		m.mu.Unlock()
		if !want {
			m.mu.Lock()
			if _, seen := m.status[name]; !seen || running {
				m.status[name] = ListenerStatus{Active: false}
			}
			m.mu.Unlock()
			continue
		}
		if running {
			continue
		}

		l, err := ingest.Start(ingest.Config{
			Name: name, Host: cfg.Bind, Port: spec.lc.Port,
			Decode: spec.decode, Source: spec.source,
		}, m.deps)

		m.mu.Lock()
		if err != nil {
			// Un bind fallito non deve impedire l'avvio dell'applicazione:
			// si registra l'errore e si prosegue con gli altri listener.
			m.metrics.Inc("listener_bind_failed", "listener", name)
			m.status[name] = ListenerStatus{Active: false, Error: err.Error()}
			log.Printf("observability: bind del listener %s su %s:%d fallito (%v); listener saltato",
				name, cfg.Bind, spec.lc.Port, err)
		} else {
			m.listeners[name] = l
			m.current[name] = bindKey{cfg.Bind, spec.lc.Port}
			m.status[name] = ListenerStatus{Active: true, Bind: cfg.Bind, Port: l.Port()}
		}
		m.mu.Unlock()
	}

	// 3. Task periodici: partono alla prima attivazione e restano attivi
	//    (sono inerti se non c'è nulla da fare).
	if cfg.Enabled {
		m.retentionOnce.Do(func() {
			tctx, cancel := context.WithCancel(context.Background())
			m.cancelTasks = cancel
			m.tasksWG.Add(3)
			go m.retentionLoop(tctx)
			go m.correlationLoop(tctx)
			go m.apiPollLoop(tctx)
		})
	}
}

// correlationLoop esegue la correlazione ogni CorrelationInterval.
func (m *Manager) correlationLoop(ctx context.Context) {
	defer m.tasksWG.Done()
	t := time.NewTicker(CorrelationInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := m.CorrelateOnce(time.Now().Unix()); err != nil {
				log.Printf("observability: errore nel ciclo di correlazione: %v", err)
			} else if n > 0 {
				log.Printf("observability: correlazione, %d eventi emessi", n)
			}
		}
	}
}

// retentionLoop esegue il pruning una volta all'ora.
func (m *Manager) retentionLoop(ctx context.Context) {
	defer m.tasksWG.Done()
	t := time.NewTicker(retentionInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cfg := m.Config()
			if _, err := m.obs.PruneOnce(cfg.RetentionDays, time.Now()); err != nil {
				log.Printf("observability: errore nel job di retention: %v", err)
			}
		}
	}
}

// Shutdown ferma listener e task periodici.
func (m *Manager) Shutdown(ctx context.Context) {
	if m.cancelTasks != nil {
		m.cancelTasks()
	}
	m.mu.Lock()
	listeners := make([]*ingest.Listener, 0, len(m.listeners))
	for name, l := range m.listeners {
		listeners = append(listeners, l)
		delete(m.listeners, name)
		delete(m.current, name)
		m.status[name] = ListenerStatus{Active: false}
	}
	m.mu.Unlock()

	for _, l := range listeners {
		l.Stop(ctx)
	}
	m.tasksWG.Wait()
}
