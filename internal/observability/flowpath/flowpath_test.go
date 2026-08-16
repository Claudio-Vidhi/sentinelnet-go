package flowpath

import (
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

type mockLookup struct {
	entries map[string]*store.ClientMapRow
}

func (m *mockLookup) ClientMap(mac, ip, sourceIP string, tenants []string, limit int) ([]*store.ClientMapRow, error) {
	if e, ok := m.entries[ip]; ok {
		return []*store.ClientMapRow{e}, nil
	}
	return nil, nil
}

func TestBuildFlowPath(t *testing.T) {
	mock := &mockLookup{
		entries: map[string]*store.ClientMapRow{
			"10.0.1.5": {
				ARPEntry: &store.ARPEntry{
					IP:         "10.0.1.5",
					MAC:        "00:11:22:33:44:55",
					SourceName: "FGT-CORE",
					SourceIP:   "10.0.0.1",
					SourceType: "fortigate",
				},
				SwitchName: "SW-ACC-01",
				SwitchIP:   "10.0.0.10",
				SwitchPort: "Gi1/0/5",
				PortVLAN:   "10",
			},
		},
	}

	res := Build(mock, "10.0.1.5", "8.8.8.8", "T1", "")
	if res.Direction != "north_south" {
		t.Errorf("got %s; want north_south", res.Direction)
	}
	if len(res.Hops) != 4 { // endpoint, access, gateway, perimeter
		t.Fatalf("expected 4 hops, got %d", len(res.Hops))
	}
	if !res.Complete {
		t.Errorf("expected complete flow path")
	}
}
