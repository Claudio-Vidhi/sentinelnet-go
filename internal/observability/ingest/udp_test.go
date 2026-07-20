package ingest

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
)

// --- doppi di test ---

type fakeResolver struct {
	byIP map[string]string
}

func (f fakeResolver) TenantForIP(ip string) (string, bool) {
	t, ok := f.byIP[ip]
	return t, ok
}

type fakeSink struct {
	mu          sync.Mutex
	flows       []string
	syslogs     []string
	quarantined []string
}

func (s *fakeSink) WriteFlow(tenant string, rec FlowRecord, receiveTS int64, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, fmt.Sprintf("%s|%s->%s|%s", tenant, rec.SrcIP, rec.DstIP, source))
}

func (s *fakeSink) WriteSyslog(tenant string, ev SyslogEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syslogs = append(s.syslogs, tenant+"|"+ev.Message)
}

func (s *fakeSink) Quarantine(exporterIP string, ts int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quarantined = append(s.quarantined, exporterIP)
}

func (s *fakeSink) snapshot() ([]string, []string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.flows...),
		append([]string(nil), s.syslogs...),
		append([]string(nil), s.quarantined...)
}

// waitFor attende che cond sia vera, per non dipendere da sleep fissi.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout in attesa di: %s", what)
}

func sendUDP(t *testing.T, port int, payload []byte) {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
}

// startTestListener avvia un listener su porta effimera di loopback.
func startTestListener(t *testing.T, decode DecodeFunc, deps *Deps) *Listener {
	t.Helper()
	l, err := Start(Config{
		Name: "test", Host: "127.0.0.1", Port: 0, Decode: decode, Source: "ipfix",
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Stop(context.Background()) })
	return l
}

// --- test ---

func TestListenerAttributesTenantAndWrites(t *testing.T) {
	sink := &fakeSink{}
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{"127.0.0.1": "TenantA"}},
		Sink:     sink,
		Metrics:  metrics.New(),
	}
	decode := func(data []byte, exporterIP string, receiveTS int64) Batch {
		return Batch{Flows: []FlowRecord{{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2", ExporterIP: exporterIP,
		}}}
	}
	l := startTestListener(t, decode, deps)
	sendUDP(t, l.Port(), []byte("qualsiasi"))

	waitFor(t, "un flusso scritto", func() bool {
		f, _, _ := sink.snapshot()
		return len(f) == 1
	})
	flows, _, _ := sink.snapshot()
	if flows[0] != "TenantA|10.0.0.1->10.0.0.2|ipfix" {
		t.Errorf("flusso = %q", flows[0])
	}
}

// Un exporter non in inventario non deve produrre scritture: i record vengono
// scartati e l'exporter finisce in quarantena. Nessun tenant di comodo.
func TestListenerDropsUnknownExporter(t *testing.T) {
	sink := &fakeSink{}
	var audits []string
	var mu sync.Mutex
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{}}, // nessuno conosciuto
		Sink:     sink,
		Metrics:  metrics.New(),
		Audit: func(msg string) {
			mu.Lock()
			audits = append(audits, msg)
			mu.Unlock()
		},
	}
	decode := func(data []byte, exporterIP string, receiveTS int64) Batch {
		return Batch{Flows: []FlowRecord{{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", ExporterIP: exporterIP}}}
	}
	l := startTestListener(t, decode, deps)
	sendUDP(t, l.Port(), []byte("x"))

	waitFor(t, "quarantena", func() bool {
		_, _, q := sink.snapshot()
		return len(q) == 1
	})
	flows, _, quarantined := sink.snapshot()
	if len(flows) != 0 {
		t.Errorf("flussi scritti = %d, attesi 0 per un exporter sconosciuto", len(flows))
	}
	if quarantined[0] != "127.0.0.1" {
		t.Errorf("quarantena = %q", quarantined[0])
	}
	counters, _ := deps.Metrics.Snapshot()
	if counters["dropped_unknown_exporter"] != 1 {
		t.Errorf("dropped_unknown_exporter = %d, atteso 1", counters["dropped_unknown_exporter"])
	}
	mu.Lock()
	n := len(audits)
	mu.Unlock()
	if n != 1 {
		t.Errorf("voci di audit = %d, attesa 1", n)
	}
}

// L'audit per exporter sconosciuto è limitato a una voce all'ora: un exporter
// mal configurato riempirebbe altrimenti il registro.
func TestListenerRateLimitsUnknownExporterAudit(t *testing.T) {
	sink := &fakeSink{}
	var audits int
	var mu sync.Mutex
	now := time.Unix(1_800_000_000, 0)
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{}},
		Sink:     sink,
		Metrics:  metrics.New(),
		Audit:    func(string) { mu.Lock(); audits++; mu.Unlock() },
		Now:      func() time.Time { return now },
	}
	decode := func(data []byte, exporterIP string, receiveTS int64) Batch {
		return Batch{Flows: []FlowRecord{{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", ExporterIP: exporterIP}}}
	}
	l := startTestListener(t, decode, deps)

	for i := 0; i < 5; i++ {
		sendUDP(t, l.Port(), []byte("x"))
	}
	waitFor(t, "cinque datagrammi in quarantena", func() bool {
		_, _, q := sink.snapshot()
		return len(q) == 5
	})
	mu.Lock()
	got := audits
	mu.Unlock()
	if got != 1 {
		t.Errorf("voci di audit = %d, attesa 1 nonostante 5 datagrammi", got)
	}
}

func TestListenerWritesSyslog(t *testing.T) {
	sink := &fakeSink{}
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{"127.0.0.1": "TenantA"}},
		Sink:     sink,
		Metrics:  metrics.New(),
	}
	decode := func(data []byte, exporterIP string, receiveTS int64) Batch {
		return Batch{Syslogs: ParseSyslog(data, exporterIP, time.Unix(receiveTS, 0))}
	}
	l := startTestListener(t, decode, deps)
	sendUDP(t, l.Port(), []byte("<134>prova messaggio"))

	waitFor(t, "un evento syslog", func() bool {
		_, s, _ := sink.snapshot()
		return len(s) == 1
	})
	_, syslogs, _ := sink.snapshot()
	if syslogs[0] != "TenantA|prova messaggio" {
		t.Errorf("evento = %q", syslogs[0])
	}
}

// Le statistiche del decoder devono finire nel registro delle metriche.
func TestListenerRecordsDecoderStats(t *testing.T) {
	sink := &fakeSink{}
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{"127.0.0.1": "T"}},
		Sink:     sink,
		Metrics:  metrics.New(),
	}
	decode := func(data []byte, exporterIP string, receiveTS int64) Batch {
		return Batch{ParseErrors: 1, CounterSamplesSkipped: 2, DataBeforeTemplateDropped: 3}
	}
	l := startTestListener(t, decode, deps)
	sendUDP(t, l.Port(), []byte("x"))

	waitFor(t, "metriche registrate", func() bool {
		c, _ := deps.Metrics.Snapshot()
		return c["counter_samples_skipped"] == 2
	})
	c, _ := deps.Metrics.Snapshot()
	if c["parse_errors{proto=test}"] != 1 {
		t.Errorf("parse_errors = %d, atteso 1 (%v)", c["parse_errors{proto=test}"], c)
	}
	if c["data_before_template_dropped"] != 3 {
		t.Errorf("data_before_template_dropped = %d, atteso 3", c["data_before_template_dropped"])
	}
	if c["datagrams_received{listener=test}"] != 1 {
		t.Errorf("datagrams_received = %d, atteso 1", c["datagrams_received{listener=test}"])
	}
}

// Stop deve sbloccare la ReadFrom e terminare, non restare appeso.
func TestListenerStopIsPrompt(t *testing.T) {
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{}},
		Sink:     &fakeSink{},
		Metrics:  metrics.New(),
	}
	l, err := Start(Config{Name: "t", Host: "127.0.0.1", Port: 0,
		Decode: func([]byte, string, int64) Batch { return Batch{} }}, deps)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { l.Stop(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop non è terminato: la ReadFrom non è stata sbloccata")
	}
}

// Due listener non possono occupare la stessa porta: il bind deve fallire con
// un errore, non andare in panic (il manager se ne serve per riportare l'esito).
func TestStartFailsOnBusyPort(t *testing.T) {
	deps := &Deps{
		Resolver: fakeResolver{byIP: map[string]string{}},
		Sink:     &fakeSink{},
		Metrics:  metrics.New(),
	}
	decode := func([]byte, string, int64) Batch { return Batch{} }
	first := startTestListener(t, decode, deps)

	if _, err := Start(Config{Name: "due", Host: "127.0.0.1", Port: first.Port(), Decode: decode}, deps); err == nil {
		t.Error("il secondo bind sulla stessa porta doveva fallire")
	}
}

func TestStartRequiresDeps(t *testing.T) {
	if _, err := Start(Config{Name: "x", Host: "127.0.0.1", Port: 0}, nil); err == nil {
		t.Error("atteso errore con dipendenze assenti")
	}
}
