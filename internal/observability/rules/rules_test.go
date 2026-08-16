package rules

import (
	"testing"
)

func TestEvaluateBlockedTraffic(t *testing.T) {
	sev := 3
	events := []EventRow{
		{
			ID:        1,
			TS:        1000,
			Tenant:    "default",
			EventType: "log.security",
			Severity:  &sev,
			SrcIP:     "10.0.1.5",
			DstIP:     "8.8.8.8",
			AttrsJSON: `{"action":"deny"}`,
		},
		{
			ID:          2,
			TS:          1010,
			Tenant:      "default",
			EventType:   "flow.aggregate",
			SrcIP:       "10.0.1.5",
			DstIP:       "8.8.8.8",
			MetricsJSON: `{"bytes": 1500}`,
		},
	}

	results := Evaluate(events, nil, []string{"BLOCKED_TRAFFIC_001"})
	if len(results) != 2 {
		t.Fatalf("expected 2 findings (trigger + supporting), got %d", len(results))
	}
	if results[0].Finding.Role != RoleTrigger {
		t.Errorf("expected trigger, got %s", results[0].Finding.Role)
	}
	if results[1].Finding.Role != RoleSupporting {
		t.Errorf("expected supporting, got %s", results[1].Finding.Role)
	}
}

func TestEvaluateFlapping(t *testing.T) {
	events := []EventRow{
		{ID: 1, TS: 100, Tenant: "T1", DeviceIP: "10.0.0.1", Interface: "Gi1/0/1", EventType: "interface.change", AttrsJSON: `{"field":"link","after":"down"}`},
		{ID: 2, TS: 120, Tenant: "T1", DeviceIP: "10.0.0.1", Interface: "Gi1/0/1", EventType: "interface.change", AttrsJSON: `{"field":"link","after":"up"}`},
		{ID: 3, TS: 140, Tenant: "T1", DeviceIP: "10.0.0.1", Interface: "Gi1/0/1", EventType: "interface.change", AttrsJSON: `{"field":"link","after":"down"}`},
		{ID: 4, TS: 160, Tenant: "T1", DeviceIP: "10.0.0.1", Interface: "Gi1/0/1", EventType: "interface.change", AttrsJSON: `{"field":"link","after":"up"}`},
	}

	results := Evaluate(events, nil, []string{"IFACE_FLAPPING_001"})
	if len(results) != 1 {
		t.Fatalf("expected 1 flapping finding, got %d", len(results))
	}
	if results[0].Finding.Role != RoleTrigger {
		t.Errorf("expected trigger role, got %s", results[0].Finding.Role)
	}
}
