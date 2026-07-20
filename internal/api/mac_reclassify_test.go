package api

import (
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/topology"
)

func reclassifyApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	return NewApp(nil, st, nil, nil), st
}

// Il cuore di D3: un avvistamento salvato come NON uplink deve diventare
// uplink appena la topologia dichiara quella porta verso un vicino, senza
// bisogno di riscansionare.
func TestReclassifyAppliesCurrentTopology(t *testing.T) {
	app, st := reclassifyApp(t)

	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	// Raccolto quando la porta sembrava di accesso.
	rows := []*store.MacSighting{{
		Mac: "aa:bb:cc:dd:ee:ff", SwitchIP: "10.0.0.1", SwitchName: "SW",
		Interface: "Gi1/0/1", IsUplink: false, Tenant: "Generale",
	}}

	// Senza topologia si conserva il valore raccolto.
	app.newMacReclassifier().apply(rows)
	if rows[0].IsUplink {
		t.Error("senza topologia il valore raccolto (non uplink) doveva essere conservato")
	}
	if rows[0].OriginType != "endpoint" {
		t.Errorf("origin_type = %q, atteso %q", rows[0].OriginType, "endpoint")
	}

	// Arriva la topologia: Gi1/0/1 va verso SW-CORE.
	if err := st.UpsertTopology("10.0.0.1", "SW", "", "",
		[]topology.Neighbor{{LocalPort: "GigabitEthernet1/0/1", RemoteHost: "SW-CORE"}},
		[]topology.PortChannel{}); err != nil {
		t.Fatal(err)
	}
	app.newMacReclassifier().apply(rows)
	if !rows[0].IsUplink {
		t.Error("con la topologia la porta doveva risultare uplink")
	}
	if rows[0].UplinkTo != "SW-CORE" {
		t.Errorf("uplink_to = %q, atteso %q", rows[0].UplinkTo, "SW-CORE")
	}
}

// Per uno switch con topologia nota, l'assenza della porta in mappa significa
// porta di accesso: un is_uplink stantio va azzerato.
func TestReclassifyClearsStaleUplink(t *testing.T) {
	app, st := reclassifyApp(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "cisco", Tenant: "Generale"}); err != nil {
		t.Fatal(err)
	}
	// La topologia conosce solo Gi1/0/24.
	if err := st.UpsertTopology("10.0.0.1", "SW", "", "",
		[]topology.Neighbor{{LocalPort: "GigabitEthernet1/0/24", RemoteHost: "SW-CORE"}},
		[]topology.PortChannel{}); err != nil {
		t.Fatal(err)
	}
	rows := []*store.MacSighting{{
		Mac: "aa:bb:cc:dd:ee:ff", SwitchIP: "10.0.0.1", SwitchName: "SW",
		Interface: "Gi1/0/1", IsUplink: true, UplinkTo: "VECCHIO-VICINO", Tenant: "Generale",
	}}
	app.newMacReclassifier().apply(rows)
	if rows[0].IsUplink || rows[0].UplinkTo != "" {
		t.Errorf("uplink stantio non azzerato: is_uplink=%v uplink_to=%q", rows[0].IsUplink, rows[0].UplinkTo)
	}
}

// I MAC delle interfacce proprie degli switch sono infrastruttura: vanno
// taggati come "switch-interface", non scartati.
func TestReclassifyTagsSwitchInterfaceMacs(t *testing.T) {
	app, st := reclassifyApp(t)

	if _, _, _, err := st.RecordSwitchIfMacs(
		[]store.IfMacInput{{Interface: "Vlan1", Mac: "aabb.ccdd.00ff"}},
		"10.0.0.1", "SW-CORE"); err != nil {
		t.Fatal(err)
	}
	rows := []*store.MacSighting{
		{Mac: "aa:bb:cc:dd:00:ff", SwitchIP: "10.0.0.9", Interface: "Gi1/0/1", Tenant: "T"},
		{Mac: "11:22:33:44:55:66", SwitchIP: "10.0.0.9", Interface: "Gi1/0/2", Tenant: "T"},
	}
	app.newMacReclassifier().apply(rows)

	if rows[0].OriginType != "switch-interface" {
		t.Errorf("origin_type = %q, atteso %q", rows[0].OriginType, "switch-interface")
	}
	if rows[0].OriginSwitch != "SW-CORE" || rows[0].OriginInterface != "Vlan1" {
		t.Errorf("origine infrastruttura errata: switch=%q iface=%q", rows[0].OriginSwitch, rows[0].OriginInterface)
	}
	if rows[1].OriginType != "endpoint" {
		t.Errorf("MAC client: origin_type = %q, atteso %q", rows[1].OriginType, "endpoint")
	}
	// Le righe restano: si taggano, non si scartano.
	if len(rows) != 2 {
		t.Errorf("righe = %d, attese 2", len(rows))
	}
}

func TestRecordSwitchIfMacsUpsert(t *testing.T) {
	_, st := reclassifyApp(t)

	in := []store.IfMacInput{
		{Interface: "Vlan1", Mac: "aabb.ccdd.00ff"},
		{Interface: "", Mac: "aabb.ccdd.0001"}, // scartata: interfaccia mancante
		{Interface: "Gi1/0/1", Mac: "non-mac"}, // scartata: MAC non valido
	}
	n, u, skip, err := st.RecordSwitchIfMacs(in, "10.0.0.1", "SW")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || u != 0 || skip != 2 {
		t.Fatalf("new=%d updated=%d skipped=%d, attesi 1/0/2", n, u, skip)
	}
	// Seconda passata sulla stessa chiave → update.
	if n, u, _, _ = st.RecordSwitchIfMacs(in[:1], "10.0.0.1", "SW-RINOMINATO"); n != 0 || u != 1 {
		t.Fatalf("new=%d updated=%d, attesi 0/1", n, u)
	}
	m, err := st.SwitchIfMacs()
	if err != nil {
		t.Fatal(err)
	}
	got, ok := m["aa:bb:cc:dd:00:ff"]
	if !ok {
		t.Fatalf("MAC non canonicalizzato nella mappa: %+v", m)
	}
	if got.SwitchName != "SW-RINOMINATO" {
		t.Errorf("switch_name = %q, atteso %q", got.SwitchName, "SW-RINOMINATO")
	}
}
