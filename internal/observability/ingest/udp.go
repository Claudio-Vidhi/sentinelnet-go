package ingest

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
)

const (
	// IngestQueueMax: datagrammi in attesa per listener.
	IngestQueueMax = 20_000
	// AuditInterval: una voce di audit per exporter sconosciuto all'ora.
	AuditInterval = time.Hour
	// readBufferSize: un datagramma UDP utile non supera i 64 KiB.
	readBufferSize = 65535
	// drainTimeout: attesa massima per svuotare la coda in chiusura.
	drainTimeout = 2 * time.Second
)

// Batch è il risultato della decodifica di un datagramma.
type Batch struct {
	Flows   []FlowRecord
	Syslogs []SyslogEvent
	// Stats sono i conteggi che il decoder non registra da sé.
	CounterSamplesSkipped     int
	ParseErrors               int
	DataBeforeTemplateDropped int
}

// DecodeFunc decodifica un datagramma. Non deve mai andare in panic.
type DecodeFunc func(data []byte, exporterIP string, receiveTS int64) Batch

// TenantResolver risolve l'IP di un exporter nel tenant del device
// corrispondente in inventario.
//
// Nel Python il lookup può segnalare una "collisione" (più device con lo
// stesso IP). Qui non serve: nella tabella devices l'IP è chiave primaria,
// quindi la collisione è strutturalmente impossibile.
type TenantResolver interface {
	TenantForIP(ip string) (tenant string, known bool)
}

// Sink riceve i record già attribuiti a un tenant.
type Sink interface {
	WriteFlow(tenant string, rec FlowRecord, receiveTS int64, source string)
	WriteSyslog(tenant string, ev SyslogEvent)
	Quarantine(exporterIP string, ts int64)
}

// Deps sono le dipendenze condivise da tutti i listener.
type Deps struct {
	Resolver TenantResolver
	Sink     Sink
	Metrics  *metrics.Registry
	// Audit registra le anomalie; può essere nil.
	Audit func(msg string)
	// Now è iniettabile nei test.
	Now func() time.Time
}

func (d *Deps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Config descrive un listener.
type Config struct {
	Name   string // ipfix | netflow | sflow | syslog
	Host   string
	Port   int
	Decode DecodeFunc
	// Source finisce nella colonna omonima di flow_aggregates ("" per syslog).
	Source string
}

type datagram struct {
	data      []byte
	srcIP     string
	receiveTS int64
}

// Listener è un listener UDP attivo.
//
// Struttura: una goroutine legge dal socket e accoda, una consuma e decodifica.
// Il Python ha bisogno di un event loop asyncio su un thread dedicato (più
// sys.setswitchinterval) solo per impedire che un burst di datagrammi affami
// l'API e il terminale WS: è un aggiramento del GIL, inutile in Go, dove le
// goroutine sono schedulate in modo preemptivo su thread reali.
type Listener struct {
	name  string
	conn  net.PacketConn
	queue chan datagram
	wg    sync.WaitGroup
	deps  *Deps

	mu              sync.Mutex
	unknownAuditted map[string]time.Time
}

// Start apre il socket e avvia lettore e consumer.
func Start(cfg Config, deps *Deps) (*Listener, error) {
	if deps == nil || deps.Sink == nil || deps.Resolver == nil {
		return nil, fmt.Errorf("listener %s: dipendenze mancanti", cfg.Name)
	}
	if deps.Metrics == nil {
		deps.Metrics = metrics.New()
	}
	conn, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", cfg.Host, cfg.Port))
	if err != nil {
		return nil, err
	}
	l := &Listener{
		name:            cfg.Name,
		conn:            conn,
		queue:           make(chan datagram, IngestQueueMax),
		deps:            deps,
		unknownAuditted: map[string]time.Time{},
	}
	l.wg.Add(2)
	go l.readLoop()
	go l.consumeLoop(cfg)
	return l, nil
}

// Port è la porta effettivamente assegnata (utile con porta 0 nei test).
func (l *Listener) Port() int {
	if a, ok := l.conn.LocalAddr().(*net.UDPAddr); ok {
		return a.Port
	}
	return 0
}

func (l *Listener) Name() string { return l.name }

// readLoop non fa altro che accodare: nessun parsing, nessun accesso al DB.
// Se la coda è piena il datagramma viene scartato, mai atteso.
func (l *Listener) readLoop() {
	defer l.wg.Done()
	defer close(l.queue)
	buf := make([]byte, readBufferSize)
	for {
		n, addr, err := l.conn.ReadFrom(buf)
		if err != nil {
			return // socket chiuso da Stop
		}
		l.deps.Metrics.Inc("datagrams_received", "listener", l.name)

		srcIP := ""
		if ua, ok := addr.(*net.UDPAddr); ok {
			srcIP = ua.IP.String()
		}
		// Copia: buf viene riusato alla lettura successiva.
		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case l.queue <- datagram{data: data, srcIP: srcIP, receiveTS: l.deps.now().Unix()}:
		default:
			l.deps.Metrics.Inc("dropped_queue_full", "listener", l.name)
		}
	}
}

func (l *Listener) consumeLoop(cfg Config) {
	defer l.wg.Done()
	processed := 0
	for dg := range l.queue {
		batch := cfg.Decode(dg.data, dg.srcIP, dg.receiveTS)
		l.recordStats(batch)
		l.dispatch(batch, dg, cfg.Source)

		processed++
		if processed%20 == 0 {
			l.deps.Metrics.SetGauge("queue_depth", len(l.queue), "listener", l.name)
		}
	}
}

func (l *Listener) recordStats(b Batch) {
	m := l.deps.Metrics
	if b.ParseErrors > 0 {
		m.Add("parse_errors", int64(b.ParseErrors), "proto", l.name)
	}
	if b.CounterSamplesSkipped > 0 {
		m.Add("counter_samples_skipped", int64(b.CounterSamplesSkipped))
	}
	if b.DataBeforeTemplateDropped > 0 {
		m.Add("data_before_template_dropped", int64(b.DataBeforeTemplateDropped))
	}
}

// dispatch attribuisce ogni record a un tenant e lo consegna al sink.
// Nessun record viene mai scritto con un tenant di comodo.
func (l *Listener) dispatch(b Batch, dg datagram, source string) {
	for _, rec := range b.Flows {
		tenant, ok := l.resolveTenant(rec.ExporterIP, dg.receiveTS)
		if !ok {
			continue
		}
		l.deps.Sink.WriteFlow(tenant, rec, dg.receiveTS, source)
	}
	for _, ev := range b.Syslogs {
		tenant, ok := l.resolveTenant(ev.ExporterIP, dg.receiveTS)
		if !ok {
			continue
		}
		l.deps.Sink.WriteSyslog(tenant, ev)
	}
}

// resolveTenant risolve l'exporter in un tenant. Un exporter sconosciuto fa
// scartare i record, li mette in quarantena e produce UNA voce di audit
// all'ora: senza il limite, un exporter mal configurato riempirebbe l'audit.
func (l *Listener) resolveTenant(exporterIP string, receiveTS int64) (string, bool) {
	tenant, known := l.deps.Resolver.TenantForIP(exporterIP)
	if known && tenant != "" {
		return tenant, true
	}
	l.deps.Metrics.Inc("dropped_unknown_exporter")
	l.deps.Sink.Quarantine(exporterIP, receiveTS)

	if l.shouldAudit(exporterIP) && l.deps.Audit != nil {
		l.deps.Audit(fmt.Sprintf(
			"Observability: datagrammi da exporter sconosciuto '%s' scartati e messi in quarantena.",
			exporterIP))
	}
	return "", false
}

func (l *Listener) shouldAudit(exporterIP string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.deps.now()
	if last, ok := l.unknownAuditted[exporterIP]; ok && now.Sub(last) < AuditInterval {
		return false
	}
	l.unknownAuditted[exporterIP] = now
	return true
}

// Stop chiude il socket e attende che la coda residua sia consumata.
// La chiusura del socket sblocca la ReadFrom in corso.
func (l *Listener) Stop(ctx context.Context) {
	_ = l.conn.Close()

	// Attesa limitata: in chiusura è meglio perdere qualche datagramma che
	// bloccare l'arresto del processo.
	deadline := time.NewTimer(drainTimeout)
	defer deadline.Stop()
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-deadline.C:
	case <-ctx.Done():
	}
}
