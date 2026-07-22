package store

import "testing"

func seedSighting(t *testing.T, s *Store, mac, switchIP, tenant string) {
	t.Helper()
	if err := s.UpsertSighting(&MacSighting{Mac: mac, SwitchIP: switchIP, Tenant: tenant, Site: "central"}); err != nil {
		t.Fatal(err)
	}
}

func TestMacStatsScoped(t *testing.T) {
	s, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })

	seedSighting(t, s, "aa:aa:aa:aa:aa:aa", "10.0.0.1", "acme")
	seedSighting(t, s, "bb:bb:bb:bb:bb:bb", "10.0.0.1", "acme")
	seedSighting(t, s, "cc:cc:cc:cc:cc:cc", "10.0.0.9", "globex")

	// Global (nil) sees all three sightings, two switches.
	sg, macs, sw, err := s.MacStatsScoped(nil)
	if err != nil {
		t.Fatal(err)
	}
	if sg != 3 || macs != 3 || sw != 2 {
		t.Fatalf("global: got sightings=%d macs=%d switches=%d, want 3/3/2", sg, macs, sw)
	}

	// Scoped to acme: two sightings, one switch.
	sg, macs, sw, _ = s.MacStatsScoped([]string{"acme"})
	if sg != 2 || macs != 2 || sw != 1 {
		t.Fatalf("acme: got %d/%d/%d, want 2/2/1", sg, macs, sw)
	}

	// Empty (non-nil) slice → all zero, no tenant visible.
	sg, macs, sw, _ = s.MacStatsScoped([]string{})
	if sg != 0 || macs != 0 || sw != 0 {
		t.Fatalf("empty scope: got %d/%d/%d, want 0/0/0", sg, macs, sw)
	}
}
