package portaction

import (
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

type mockClientLookup struct {
	rows []*store.ClientMapRow
}

func (m *mockClientLookup) ClientMap(mac, ip, sourceIP string, tenants []string, limit int) ([]*store.ClientMapRow, error) {
	return m.rows, nil
}

func TestBuildCommands(t *testing.T) {
	down, up, err := BuildCommands("cisco_ios", "GigabitEthernet1/0/5")
	if err != nil {
		t.Fatalf("BuildCommands failed: %v", err)
	}
	if len(down) != 2 || down[0] != "interface GigabitEthernet1/0/5" || down[1] != "shutdown" {
		t.Errorf("unexpected down commands: %v", down)
	}
	if len(up) != 2 || up[0] != "interface GigabitEthernet1/0/5" || up[1] != "no shutdown" {
		t.Errorf("unexpected up commands: %v", up)
	}

	// Invalid interface with command injection attempt
	_, _, err = BuildCommands("cisco_ios", "Gi1/0/1\nreload")
	if err == nil {
		t.Errorf("expected validation error for interface with newline")
	}
}

func TestVerifyPort(t *testing.T) {
	mock := &mockClientLookup{
		rows: []*store.ClientMapRow{
			{
				ARPEntry:   &store.ARPEntry{MAC: "00:11:22:33:44:55"},
				SwitchIP:   "10.0.0.10",
				SwitchName: "SW-01",
				SwitchPort: "Gi1/0/10",
			},
		},
	}

	ok, reason := VerifyPort(mock, "00:11:22:33:44:55", "10.0.0.10", "Gi1/0/10", nil)
	if !ok {
		t.Errorf("expected ok=true, got reason: %s", reason)
	}

	ok, reason = VerifyPort(mock, "00:11:22:33:44:55", "10.0.0.10", "Gi1/0/11", nil)
	if ok {
		t.Errorf("expected ok=false for wrong port")
	}
}
