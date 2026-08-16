package obsstore

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
)

func TestIncidentsStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "obs.db")
	s, err := Open(dbPath, metrics.New())
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	now := time.Now().Unix()

	// 1. Insert unassigned evidence
	_, err = s.DB.Exec(
		`INSERT INTO evidence (created_ts, ts, tenant, entity_key, role, rule_id, rule_version, params_json, severity, summary, status)
		 VALUES (?, ?, 'T1', 'ip:192.168.1.50', 'trigger', 'IFACE_FLAPPING_001', '1.0.0', '{}', 3, 'Flapping Gi1/0/1', 'active')`,
		now, now)
	if err != nil {
		t.Fatalf("insert evidence: %v", err)
	}

	// 2. Run GroupAndReasonIncidents
	linked, err := s.GroupAndReasonIncidents(now, nil)
	if err != nil {
		t.Fatalf("GroupAndReasonIncidents failed: %v", err)
	}
	if linked != 1 {
		t.Fatalf("expected 1 linked evidence, got %d", linked)
	}

	// 3. List incidents
	incs, err := s.ListIncidents(now-3600, "new", []string{"T1"}, 10, 0)
	if err != nil {
		t.Fatalf("ListIncidents failed: %v", err)
	}
	if len(incs) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(incs))
	}
	inc := incs[0]
	if inc.EntityKey != "ip:192.168.1.50" {
		t.Errorf("entity key = %s; want ip:192.168.1.50", inc.EntityKey)
	}
	if inc.CauseKind != "IFACE_FLAPPING_001" {
		t.Errorf("cause kind = %s; want IFACE_FLAPPING_001", inc.CauseKind)
	}

	// 4. Update status
	ok, err := s.UpdateIncidentStatus(inc.ID, "new", "ack")
	if err != nil || !ok {
		t.Fatalf("UpdateIncidentStatus failed: ok=%v, err=%v", ok, err)
	}

	// 5. Check detail
	detail, err := s.GetIncident(inc.ID)
	if err != nil || detail == nil {
		t.Fatalf("GetIncident failed: %v", err)
	}
	if detail.Status != "ack" {
		t.Errorf("detail status = %s; want ack", detail.Status)
	}
}
