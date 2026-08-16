package pingmon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestPingMonitorLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.Open(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.DB.Close()

	// Add test devices
	_ = st.UpsertDevice(&store.Device{IP: "10.0.0.1", Hostname: "GW-1", Tenant: "T1"})
	_ = st.UpsertDevice(&store.Device{IP: "10.0.0.2", Hostname: "SW-1", Tenant: "T2"})

	mon := New(st, func(msg string) {})

	// Custom probe func: 10.0.0.1 is up, 10.0.0.2 is down
	mon.SetProbeFunc(func(ctx context.Context, host string) bool {
		return host == "10.0.0.1"
	})

	// 1. Initial config
	cfg := mon.GetConfig()
	if cfg.Enabled {
		t.Errorf("expected disabled by default")
	}

	// 2. Save config
	saved, err := mon.SaveConfig(true, 10, "admin")
	if err != nil || !saved.Enabled || saved.IntervalSeconds != 10 {
		t.Fatalf("SaveConfig failed: %v, %+v", err, saved)
	}

	// 3. Run cycle
	mon.RunCycle()

	// 4. Check status
	status := mon.GetStatus(nil)
	if status.Summary.Total != 2 || status.Summary.Up != 1 || status.Summary.Down != 1 {
		t.Fatalf("unexpected summary: %+v", status.Summary)
	}

	// 5. Scoped status (only T1)
	scopedStatus := mon.GetStatus([]string{"T1"})
	if scopedStatus.Summary.Total != 1 || scopedStatus.Summary.Up != 1 {
		t.Fatalf("unexpected scoped summary: %+v", scopedStatus.Summary)
	}
}

