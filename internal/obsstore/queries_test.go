package obsstore

import (
	"testing"
	"time"
)

func intp(v int) *int { return &v }

func TestTopFlowsContext(t *testing.T) {
	s, err := Open(t.TempDir()+"/obs.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })

	now := time.Now().Unix()
	ins := func(tenant, src, dst string, proto, dport int, bytes, pkts int64) {
		_, e := s.DB.Exec(`INSERT INTO flow_aggregates
			(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
			VALUES (?,?,?,?,?,?,?,?,1)`, now-60, tenant, src, dst, proto, dport, bytes, pkts)
		if e != nil {
			t.Fatal(e)
		}
	}
	ins("acme", "10.0.0.1", "8.8.8.8", 6, 443, 5000, 50)
	ins("acme", "10.0.0.2", "1.1.1.1", 17, 53, 100, 2)
	ins("globex", "10.9.9.9", "8.8.4.4", 6, 80, 9999, 99)

	cutoff := now - 900

	// Scope acme → only acme rows, ordered by bytes desc.
	flows, _, err := s.TopFlowsContext(cutoff, []string{"acme"}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("acme scope: got %d flows, want 2", len(flows))
	}
	if flows[0].SrcIP != "10.0.0.1" || flows[0].TotalBytes != 5000 {
		t.Errorf("order/bytes wrong: %+v", flows[0])
	}
	if flows[0].DstPort == nil || *flows[0].DstPort != 443 {
		t.Errorf("dst_port not carried: %+v", flows[0].DstPort)
	}

	// keys constraint: only the udp/53 tuple.
	flows, _, _ = s.TopFlowsContext(cutoff, []string{"acme"}, []FlowKey{
		{SrcIP: "10.0.0.2", DstIP: "1.1.1.1", Protocol: 17, DstPort: intp(53)},
	}, 20)
	if len(flows) != 1 || flows[0].SrcIP != "10.0.0.2" {
		t.Fatalf("keys constraint: got %d flows, want 1 (10.0.0.2)", len(flows))
	}

	// Scope must not leak globex even if a key names it.
	flows, _, _ = s.TopFlowsContext(cutoff, []string{"acme"}, []FlowKey{
		{SrcIP: "10.9.9.9", DstIP: "8.8.4.4", Protocol: 6, DstPort: intp(80)},
	}, 20)
	if len(flows) != 0 {
		t.Fatalf("scope leak: got %d flows, want 0", len(flows))
	}
}

func TestTopFlowsContextAnomalies(t *testing.T) {
	s, err := Open(t.TempDir()+"/obs.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	now := time.Now().Unix()
	_, err = s.DB.Exec(`INSERT INTO correlated_events
		(created_ts, tenant, kind, src_ip, dst_ip, switch_port, severity, status)
		VALUES (?,?,?,?,?,?,?,?)`, now-100, "acme", "scan", "10.0.0.5", "10.0.0.6", "Gi0/1", 3, "new")
	if err != nil {
		t.Fatal(err)
	}
	// A resolved one must be excluded.
	_, _ = s.DB.Exec(`INSERT INTO correlated_events
		(created_ts, tenant, kind, src_ip, dst_ip, switch_port, severity, status)
		VALUES (?,?,?,?,?,?,?,?)`, now-100, "acme", "old", "1.1.1.1", "2.2.2.2", "", 1, "resolved")

	_, anomalies, err := s.TopFlowsContext(now-900, []string{"acme"}, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(anomalies) != 1 || anomalies[0].Kind != "scan" {
		t.Fatalf("anomalies: got %d (want 1 'scan'): %+v", len(anomalies), anomalies)
	}
}
