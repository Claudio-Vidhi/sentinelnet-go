package metrics

import (
	"sync"
	"testing"
	"time"
)

func TestCountersAndGauges(t *testing.T) {
	r := New()
	r.Inc("pkts")
	r.Inc("pkts")
	r.Add("bytes", 1500)
	r.SetGauge("listeners", 3)

	counters, gauges := r.Snapshot()
	if counters["pkts"] != 2 {
		t.Errorf("pkts = %d, atteso 2", counters["pkts"])
	}
	if counters["bytes"] != 1500 {
		t.Errorf("bytes = %d, atteso 1500", counters["bytes"])
	}
	if gauges["listeners"] != 3 {
		t.Errorf("listeners = %v, atteso 3", gauges["listeners"])
	}
}

// Le label vanno ordinate, così la stessa coppia produce sempre la stessa chiave.
func TestLabelKeyIsStable(t *testing.T) {
	r := New()
	r.Inc("drops", "kind", "sflow", "exporter", "10.0.0.1")
	r.Inc("drops", "exporter", "10.0.0.1", "kind", "sflow")

	counters, _ := r.Snapshot()
	want := "drops{exporter=10.0.0.1,kind=sflow}"
	if counters[want] != 2 {
		t.Errorf("chiave %q = %d, atteso 2 — le label non sono ordinate: %v", want, counters[want], counters)
	}
}

func TestShouldWarnRateLimits(t *testing.T) {
	r := New()
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }

	if !r.ShouldWarn("exporter-sconosciuto") {
		t.Fatal("primo WARN: atteso true")
	}
	if r.ShouldWarn("exporter-sconosciuto") {
		t.Error("secondo WARN immediato: atteso false")
	}
	// Chiave diversa: non condivide il rate limit.
	if !r.ShouldWarn("altra-chiave") {
		t.Error("chiave diversa: atteso true")
	}
	// Passato l'intervallo, si torna a loggare.
	now = now.Add(WarnInterval)
	if !r.ShouldWarn("exporter-sconosciuto") {
		t.Error("dopo WarnInterval: atteso true")
	}
}

// Lo snapshot è una copia: mutarlo non deve toccare il registro.
func TestSnapshotIsCopy(t *testing.T) {
	r := New()
	r.Inc("x")
	counters, gauges := r.Snapshot()
	counters["x"] = 999
	gauges["nuovo"] = true

	counters2, gauges2 := r.Snapshot()
	if counters2["x"] != 1 {
		t.Errorf("x = %d, atteso 1: lo snapshot condivide la mappa", counters2["x"])
	}
	if _, ok := gauges2["nuovo"]; ok {
		t.Error("la gauge aggiunta allo snapshot è finita nel registro")
	}
}

func TestConcurrentUse(t *testing.T) {
	r := New()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Inc("pkts")
				r.SetGauge("last", i)
				r.Snapshot()
			}
		}()
	}
	wg.Wait()
	if counters, _ := r.Snapshot(); counters["pkts"] != 800 {
		t.Errorf("pkts = %d, attesi 800", counters["pkts"])
	}
}
