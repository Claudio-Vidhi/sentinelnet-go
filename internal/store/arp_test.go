package store

import (
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s
}

func TestRecordARPEntriesUpsert(t *testing.T) {
	s := testStore(t)

	rows := []ARPInput{
		{MAC: "aabb.ccdd.eeff", IP: "10.0.0.5", VLAN: "10", Interface: "Vlan10"},
		{MAC: "00:11:22:33:44:55", IP: "10.0.0.6"},
		{MAC: "non-un-mac", IP: "10.0.0.7"}, // scartata
		{MAC: "aabb.ccdd.0001", IP: ""},     // scartata: IP mancante
	}
	c, err := s.RecordARPEntries(rows, "10.0.0.1", "GW", "switch", "TenantA", "")
	if err != nil {
		t.Fatalf("RecordARPEntries: %v", err)
	}
	if c.New != 2 || c.Updated != 0 || c.Skipped != 2 {
		t.Fatalf("counts = %+v, attesi new=2 updated=0 skipped=2", c)
	}

	// Il MAC deve essere canonicalizzato indipendentemente dal formato d'origine.
	got, err := s.SearchARP("aabb.ccdd.eeff", "", "", nil, 100)
	if err != nil {
		t.Fatalf("SearchARP: %v", err)
	}
	if len(got) != 1 || got[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC non canonicalizzato: %+v", got)
	}
	if got[0].Site != "central" {
		t.Errorf("site = %q, atteso il default %q", got[0].Site, "central")
	}

	// Seconda registrazione: stesso (mac, ip, source_ip) → update, non insert.
	c2, _ := s.RecordARPEntries(rows[:1], "10.0.0.1", "GW", "switch", "TenantA", "")
	if c2.New != 0 || c2.Updated != 1 {
		t.Fatalf("counts = %+v, attesi new=0 updated=1", c2)
	}
	got, _ = s.SearchARP("aabb.ccdd.eeff", "", "", nil, 100)
	if got[0].SeenCount != 2 {
		t.Errorf("seen_count = %d, atteso 2", got[0].SeenCount)
	}

	// Stesso binding da un ALTRO gateway → riga separata (una per gateway).
	c3, _ := s.RecordARPEntries(rows[:1], "10.0.0.2", "GW2", "switch", "TenantA", "")
	if c3.New != 1 {
		t.Fatalf("counts = %+v, atteso new=1 per un source_ip diverso", c3)
	}
}

func TestSearchARPFilters(t *testing.T) {
	s := testStore(t)
	_, _ = s.RecordARPEntries([]ARPInput{
		{MAC: "aabb.ccdd.eeff", IP: "10.0.0.5"},
		{MAC: "aabb.ccdd.0002", IP: "10.0.1.9"},
	}, "10.0.0.1", "GW", "switch", "TenantA", "")

	// Frammento/OUI: ricerca parziale ignorando i separatori.
	if got, _ := s.SearchARP("aabbcc", "", "", nil, 100); len(got) != 2 {
		t.Errorf("ricerca per frammento = %d risultati, attesi 2", len(got))
	}
	// Prefisso IP.
	if got, _ := s.SearchARP("", "10.0.1", "", nil, 100); len(got) != 1 {
		t.Errorf("ricerca per prefisso IP = %d risultati, atteso 1", len(got))
	}
	// source_ip inesistente.
	if got, _ := s.SearchARP("", "", "192.168.9.9", nil, 100); len(got) != 0 {
		t.Errorf("source_ip inesistente = %d risultati, attesi 0", len(got))
	}
	// Slice di tenant vuota = nessun risultato (utente senza tenant visibili).
	if got, _ := s.SearchARP("", "", "", []string{}, 100); len(got) != 0 {
		t.Errorf("scope vuoto = %d risultati, attesi 0", len(got))
	}
	// nil = nessuna restrizione (admin).
	if got, _ := s.SearchARP("", "", "", nil, 100); len(got) != 2 {
		t.Errorf("scope nil = %d risultati, attesi 2", len(got))
	}
}

// Verifica centrale: lo stesso MAC e lo stesso IP RFC1918 esistono in due
// tenant diversi (sedi diverse dietro NAT). La posizione fisica di un tenant
// NON deve mai comparire nel binding ARP dell'altro.
func TestClientMapDoesNotLeakAcrossTenants(t *testing.T) {
	s := testStore(t)
	const sharedMAC = "aa:bb:cc:dd:ee:ff"

	// Stesso MAC e stesso IP RFC1918, ma gateway distinti: due sedi dietro NAT.
	// (La chiave di upsert è (mac, ip, source_ip): sedi diverse hanno gateway
	// diversi, quindi restano due righe.)
	_, _ = s.RecordARPEntries([]ARPInput{{MAC: sharedMAC, IP: "192.168.1.50"}},
		"192.168.1.1", "GW-A", "switch", "TenantA", "sedeA")
	_, _ = s.RecordARPEntries([]ARPInput{{MAC: sharedMAC, IP: "192.168.1.50"}},
		"192.168.2.1", "GW-B", "switch", "TenantB", "sedeB")

	// Posizione fisica distinta per ciascun tenant.
	if err := s.UpsertSighting(&MacSighting{
		Mac: sharedMAC, SwitchIP: "10.1.1.1", SwitchName: "SW-A",
		Interface: "Gi1/0/1", Vlan: "10", Tenant: "TenantA",
	}); err != nil {
		t.Fatalf("UpsertSighting A: %v", err)
	}
	if err := s.UpsertSighting(&MacSighting{
		Mac: sharedMAC, SwitchIP: "10.2.2.2", SwitchName: "SW-B",
		Interface: "Gi2/0/2", Vlan: "20", Tenant: "TenantB",
	}); err != nil {
		t.Fatalf("UpsertSighting B: %v", err)
	}

	rows, err := s.ClientMap("", "", "", []string{"TenantA"}, 100)
	if err != nil {
		t.Fatalf("ClientMap: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("righe = %d, attesa 1 (solo TenantA)", len(rows))
	}
	r := rows[0]
	if r.Tenant != "TenantA" {
		t.Fatalf("tenant = %q, atteso TenantA", r.Tenant)
	}
	if r.SwitchIP != "10.1.1.1" || r.SwitchPort != "Gi1/0/1" {
		t.Errorf("posizione errata: switch=%q porta=%q — attesi 10.1.1.1/Gi1/0/1", r.SwitchIP, r.SwitchPort)
	}
	if r.SwitchIP == "10.2.2.2" || r.SwitchName == "SW-B" {
		t.Fatal("FUGA FRA TENANT: la posizione di TenantB è comparsa nel binding di TenantA")
	}
}

// Gli uplink non sono posizioni di accesso: non devono popolare la client map.
func TestClientMapExcludesUplinks(t *testing.T) {
	s := testStore(t)
	const m = "aa:bb:cc:dd:ee:01"
	_, _ = s.RecordARPEntries([]ARPInput{{MAC: m, IP: "10.0.0.5"}},
		"10.0.0.1", "GW", "switch", "T", "")
	_ = s.UpsertSighting(&MacSighting{
		Mac: m, SwitchIP: "10.1.1.1", SwitchName: "SW", Interface: "Te1/1/1",
		Vlan: "10", Tenant: "T", IsUplink: true,
	})

	rows, err := s.ClientMap("", "", "", []string{"T"}, 100)
	if err != nil {
		t.Fatalf("ClientMap: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("righe = %d, attesa 1", len(rows))
	}
	if rows[0].SwitchPort != "" {
		t.Errorf("porta = %q, attesa vuota: l'unico avvistamento è un uplink", rows[0].SwitchPort)
	}
}

// Senza assegnazione manuale il tipo resta generico: non si eredita mai
// source_type, che descrive il gateway e non il client.
func TestClientMapClientType(t *testing.T) {
	s := testStore(t)
	_, _ = s.RecordARPEntries([]ARPInput{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.5"},
		{MAC: "aa:bb:cc:dd:ee:02", IP: "10.0.0.6"},
	}, "10.0.0.1", "GW", "firewall", "T", "")

	if err := s.AssignMeta("10.0.0.6", map[string]string{"category": "stampante"}); err != nil {
		t.Fatalf("AssignMeta: %v", err)
	}
	rows, err := s.ClientMap("", "", "", nil, 100)
	if err != nil {
		t.Fatalf("ClientMap: %v", err)
	}
	byIP := map[string]string{}
	for _, r := range rows {
		byIP[r.IP] = r.ClientType
	}
	if byIP["10.0.0.5"] != "client" {
		t.Errorf("client_type senza assegnazione = %q, atteso %q", byIP["10.0.0.5"], "client")
	}
	if byIP["10.0.0.6"] != "stampante" {
		t.Errorf("client_type assegnato = %q, atteso %q", byIP["10.0.0.6"], "stampante")
	}
}

func TestARPStatsScoped(t *testing.T) {
	s := testStore(t)
	_, _ = s.RecordARPEntries([]ARPInput{
		{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.5"},
		{MAC: "aa:bb:cc:dd:ee:02", IP: "10.0.0.6"},
	}, "10.0.0.1", "GW-A", "switch", "TenantA", "")
	_, _ = s.RecordARPEntries([]ARPInput{{MAC: "aa:bb:cc:dd:ee:03", IP: "10.9.0.5"}},
		"10.9.0.1", "GW-B", "switch", "TenantB", "")

	b, m, src, err := s.ARPStats(nil)
	if err != nil {
		t.Fatalf("ARPStats: %v", err)
	}
	if b != 3 || m != 3 || src != 2 {
		t.Errorf("admin: bindings=%d macs=%d sources=%d, attesi 3/3/2", b, m, src)
	}
	if b, m, src, _ = s.ARPStats([]string{"TenantA"}); b != 2 || m != 2 || src != 1 {
		t.Errorf("TenantA: bindings=%d macs=%d sources=%d, attesi 2/2/1", b, m, src)
	}
	if b, _, _, _ = s.ARPStats([]string{}); b != 0 {
		t.Errorf("scope vuoto: bindings=%d, atteso 0", b)
	}
}

func TestPruneARP(t *testing.T) {
	s := testStore(t)
	_, _ = s.RecordARPEntries([]ARPInput{{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.5"}},
		"10.0.0.1", "GW", "switch", "T", "")

	// Retention ampia: nulla da eliminare.
	if n, err := s.PruneARP(30); err != nil || n != 0 {
		t.Fatalf("PruneARP(30) = %d, %v — attesi 0, nil", n, err)
	}
	// Retention negativa: il cutoff è nel futuro, la riga viene eliminata.
	if n, err := s.PruneARP(-1); err != nil || n != 1 {
		t.Fatalf("PruneARP(-1) = %d, %v — attesi 1, nil", n, err)
	}
}
