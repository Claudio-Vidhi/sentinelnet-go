package obsstore

import (
	"testing"
	"time"
)

func seedFlow(t *testing.T, s *Store, windowStart int64, src string) {
	t.Helper()
	s.EnqueueWrite(`INSERT INTO flow_aggregates
		(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
		VALUES (?,?,?,?,?,?,?,?,1)`, windowStart, "T", src, "10.0.0.2", 6, 443, 100, 1)
}

func count(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPruneOnceRespectsRetentionWindow(t *testing.T) {
	s := testStore(t)
	now := time.Unix(1_800_000_000, 0)

	seedFlow(t, s, now.Unix()-40*86400, "10.0.0.1") // oltre i 30 giorni
	seedFlow(t, s, now.Unix()-1*86400, "10.0.0.3")  // dentro la finestra
	s.Sync()

	deleted, err := s.PruneOnce(RetentionDays{FlowAggregates: 30}, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["flow_aggregates"] != 1 {
		t.Errorf("eliminate = %d, attesa 1", deleted["flow_aggregates"])
	}
	if n := count(t, s, "flow_aggregates"); n != 1 {
		t.Errorf("righe rimaste = %d, attesa 1", n)
	}
}

// Retention a 0 significa "non eliminare nulla".
func TestPruneOnceDisabledForZeroDays(t *testing.T) {
	s := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	seedFlow(t, s, now.Unix()-400*86400, "10.0.0.1")
	s.Sync()

	deleted, err := s.PruneOnce(RetentionDays{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 0 {
		t.Errorf("eliminazioni = %v, attese nessuna", deleted)
	}
	if n := count(t, s, "flow_aggregates"); n != 1 {
		t.Errorf("righe = %d, attesa 1", n)
	}
}

// Gli eventi correlati ancora aperti non vengono MAI eliminati: sono
// segnalazioni non gestite, non dati di telemetria da minimizzare.
func TestPruneOnceKeepsUnresolvedCorrelatedEvents(t *testing.T) {
	s := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	old := now.Unix() - 400*86400

	for i, status := range []string{"new", "ack", "resolved"} {
		s.EnqueueWrite(`INSERT INTO correlated_events (created_ts, tenant, kind, status, dedup_key)
			VALUES (?,?,?,?,?)`, old, "T", "prova", status, i)
	}
	s.Sync()

	deleted, err := s.PruneOnce(RetentionDays{CorrelatedEvents: 90}, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["correlated_events"] != 1 {
		t.Errorf("eliminati = %d, atteso 1 (solo quelli risolti)", deleted["correlated_events"])
	}
	if n := count(t, s, "correlated_events"); n != 2 {
		t.Errorf("rimasti = %d, attesi 2 (new e ack)", n)
	}
}

// I DELETE sono batchati: con più righe del batch il ciclo deve comunque
// eliminarle tutte e terminare.
func TestPruneOnceHandlesMoreRowsThanBatch(t *testing.T) {
	s := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	old := now.Unix() - 40*86400

	for i := 0; i < BatchRows+25; i++ {
		s.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, message) VALUES (?,?,?)`,
			old, "T", "vecchio")
	}
	s.Sync()

	deleted, err := s.PruneOnce(RetentionDays{SyslogEvents: 7}, now)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["syslog_events"] != int64(BatchRows+25) {
		t.Errorf("eliminati = %d, attesi %d", deleted["syslog_events"], BatchRows+25)
	}
	if n := count(t, s, "syslog_events"); n != 0 {
		t.Errorf("righe rimaste = %d, attese 0", n)
	}
}

func TestPruneOnceSetsGauge(t *testing.T) {
	s := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	if _, err := s.PruneOnce(RetentionDays{FlowAggregates: 30}, now); err != nil {
		t.Fatal(err)
	}
	_, gauges := s.Metrics.Snapshot()
	if gauges["last_prune_ts"] != now.Unix() {
		t.Errorf("last_prune_ts = %v, atteso %d", gauges["last_prune_ts"], now.Unix())
	}
}
