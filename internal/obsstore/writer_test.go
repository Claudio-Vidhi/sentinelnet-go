package obsstore

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "obs.db"), nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationCreatesTables(t *testing.T) {
	s := testStore(t)
	for _, tbl := range []string{
		"flow_aggregates", "syslog_events", "correlated_events",
		"api_observations", "quarantined_exporters",
	} {
		var n int
		if err := s.DB.QueryRow(
			`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("tabella %q assente", tbl)
		}
	}
}

// L'UPSERT deve accumulare byte e pacchetti nella stessa finestra, non
// sovrascrivere: è il cuore dell'aggregazione al minuto.
func TestEnqueueFlowAggregates(t *testing.T) {
	s := testStore(t)
	const ts = 1_800_000_000 // istante fisso, niente dipendenza dall'orologio

	for i := 0; i < 3; i++ {
		s.EnqueueFlow(Flow{
			Tenant: "T", SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			Protocol: 6, DstPort: 443, TotalBytes: 100, TotalPackets: 2,
			ExporterIP: "10.0.0.9", Source: "ipfix",
			ExportTS: ts, ReceiveTS: ts,
		})
	}
	s.Sync()

	var bytes, packets, count int64
	if err := s.DB.QueryRow(
		`SELECT total_bytes, total_packets, flow_count FROM flow_aggregates`).
		Scan(&bytes, &packets, &count); err != nil {
		t.Fatal(err)
	}
	if bytes != 300 || packets != 6 || count != 3 {
		t.Errorf("bytes=%d packets=%d flow_count=%d, attesi 300/6/3", bytes, packets, count)
	}
}

// Flussi in minuti diversi devono finire in righe diverse.
func TestFlowWindowSeparatesMinutes(t *testing.T) {
	s := testStore(t)
	const ts = 1_800_000_000
	f := Flow{Tenant: "T", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Protocol: 6, DstPort: 443,
		TotalBytes: 10, TotalPackets: 1, Source: "ipfix"}

	f.ExportTS, f.ReceiveTS = ts, ts
	s.EnqueueFlow(f)
	f.ExportTS, f.ReceiveTS = ts+60, ts+60
	s.EnqueueFlow(f)
	s.Sync()

	var rows int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM flow_aggregates`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("righe = %d, attese 2 (due finestre distinte)", rows)
	}
}

func TestFlowWindowStart(t *testing.T) {
	s := testStore(t)
	const now = 1_800_000_030 // 30s dentro il minuto

	// Timestamp exporter plausibile: si usa quello, troncato al minuto.
	if got := s.FlowWindowStart(now, now); got != 1_800_000_000 {
		t.Errorf("window = %d, attesa 1800000000", got)
	}
	// Exporter con orologio molto sfasato: si ricade sul tempo di ricezione.
	if got := s.FlowWindowStart(now+10_000, now); got != 1_800_000_000 {
		t.Errorf("clock skew: window = %d, attesa 1800000000", got)
	}
	counters, _ := s.Metrics.Snapshot()
	if counters["clock_skew_fallback"] != 1 {
		t.Errorf("clock_skew_fallback = %d, atteso 1", counters["clock_skew_fallback"])
	}
	// Timestamp assente: tempo di ricezione, senza contare uno skew.
	if got := s.FlowWindowStart(0, now); got != 1_800_000_000 {
		t.Errorf("senza export_ts: window = %d, attesa 1800000000", got)
	}
	if counters, _ = s.Metrics.Snapshot(); counters["clock_skew_fallback"] != 1 {
		t.Errorf("clock_skew_fallback = %d, atteso ancora 1", counters["clock_skew_fallback"])
	}
}

// Una scrittura malformata non deve far cadere il batch né fermare il writer.
func TestBadWriteDoesNotKillWriter(t *testing.T) {
	s := testStore(t)
	s.EnqueueWrite(`INSERT INTO tabella_inesistente(x) VALUES(?)`, 1)
	s.EnqueueWrite(`INSERT INTO quarantined_exporters(exporter_ip, first_seen, last_seen, packet_count)
	                VALUES(?,?,?,?)`, "10.0.0.9", 1, 2, 3)
	s.Sync()

	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM quarantined_exporters`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("righe valide scritte = %d, attesa 1: una scrittura errata ha fatto cadere il batch", n)
	}
	counters, _ := s.Metrics.Snapshot()
	if counters["writes_dropped_error"] != 1 {
		t.Errorf("writes_dropped_error = %d, atteso 1", counters["writes_dropped_error"])
	}
	if counters["writes_ok"] != 1 {
		t.Errorf("writes_ok = %d, atteso 1", counters["writes_ok"])
	}
}

// La coda piena scarta senza bloccare: l'ingest UDP non deve mai attendere.
func TestQueueFullDropsInsteadOfBlocking(t *testing.T) {
	s := testStore(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < QueueMax*2; i++ {
			s.EnqueueWrite(`INSERT INTO quarantined_exporters(exporter_ip) VALUES(?)`, i)
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("EnqueueWrite ha bloccato: la coda piena deve scartare, non attendere")
	}
}

func TestConcurrentEnqueue(t *testing.T) {
	s := testStore(t)
	var wg sync.WaitGroup
	const workers, each = 8, 50
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				s.EnqueueFlow(Flow{
					Tenant: "T", SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
					Protocol: 6, DstPort: 443, TotalBytes: 1, TotalPackets: 1,
					Source: "ipfix", ExportTS: 1_800_000_000, ReceiveTS: 1_800_000_000,
				})
			}
		}(w)
	}
	wg.Wait()
	s.Sync()

	var bytes int64
	if err := s.DB.QueryRow(`SELECT total_bytes FROM flow_aggregates`).Scan(&bytes); err != nil {
		t.Fatal(err)
	}
	if bytes != workers*each {
		t.Errorf("total_bytes = %d, attesi %d", bytes, workers*each)
	}
}

// Close deve svuotare la coda, non perdere le scritture in sospeso.
func TestCloseFlushesPendingWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "obs.db")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		s.EnqueueWrite(`INSERT INTO syslog_events(ts, tenant, message) VALUES(?,?,?)`,
			1_800_000_000, "T", "messaggio")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	if err := s2.DB.QueryRow(`SELECT COUNT(*) FROM syslog_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 100 {
		t.Errorf("righe = %d, attese 100: Close non ha svuotato la coda", n)
	}
}
