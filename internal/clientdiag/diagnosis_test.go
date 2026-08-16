package clientdiag

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestClientDiagnosisLifecycle(t *testing.T) {
	tmpDir := t.TempDir()
	st, err := store.Open(filepath.Join(tmpDir, "inv.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer st.DB.Close()

	obs, err := obsstore.Open(filepath.Join(tmpDir, "obs.db"), metrics.New())
	if err != nil {
		t.Fatalf("obs Open failed: %v", err)
	}
	defer obs.Close()

	// Insert ARP and MAC entries
	_, _ = st.RecordARPEntries([]store.ARPInput{
		{IP: "192.168.1.55", MAC: "001122334455"},
	}, "192.168.1.1", "FGT-CORE", "fortigate", "T1", "HQ")

	_ = st.UpsertSighting(&store.MacSighting{
		Mac:        "00:11:22:33:44:55",
		SwitchIP:   "10.0.0.10",
		SwitchName: "SW-CORE",
		Interface:  "Gi1/0/5",
		Vlan:       "10",
		Tenant:     "T1",
		Site:       "HQ",
	})

	req := Request{
		Client: "192.168.1.55",
		Dest:   "8.8.8.8",
	}

	rep, err := Diagnose(context.Background(), st, obs, req)
	if err != nil {
		t.Fatalf("Diagnose failed: %v", err)
	}

	if rep.Client != "192.168.1.55" || rep.QueryType != "ip" {
		t.Errorf("unexpected client query: %+v", rep)
	}
	if !rep.L2.Known || rep.L2.SwitchPort != "Gi1/0/5" {
		t.Errorf("expected L2 known on Gi1/0/5, got %+v", rep.L2)
	}
	if !rep.L3.Known || rep.L3.GatewayIP != "192.168.1.1" {
		t.Errorf("expected L3 gateway 192.168.1.1, got %+v", rep.L3)
	}
	if !rep.Flowpath.Known || len(rep.Flowpath.Hops) == 0 {
		t.Errorf("expected flowpath hops to be populated")
	}
	if !rep.Complete {
		t.Errorf("expected complete report when L2 and L3 known")
	}
}

