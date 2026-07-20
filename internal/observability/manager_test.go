package observability

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func testManager(t *testing.T) (*Manager, *obsstore.Store, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	obs, err := obsstore.Open(filepath.Join(dir, "obs.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { obs.Close(); st.DB.Close() })

	m := NewManager(obs, st, nil)
	t.Cleanup(func() { m.Shutdown(context.Background()) })
	return m, obs, st
}

// freePort trova una porta UDP libera. C'è una piccola finestra di corsa fra
// la chiusura e il riuso, accettabile in test.
func freePort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	return p
}

func enabledConfig(port int) Config {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Bind = "127.0.0.1"
	cfg.Syslog = ListenerConfig{Enabled: true, Port: port}
	return cfg
}

func TestApplyStartsAndStopsListeners(t *testing.T) {
	m, _, _ := testManager(t)
	ctx := context.Background()

	m.Apply(ctx, enabledConfig(freePort(t)))
	st := m.Status()
	if !st["syslog"].Active {
		t.Fatalf("syslog non attivo: %+v", st)
	}
	// Gli altri protocolli restano dichiarati non attivi, non assenti.
	for _, name := range []string{"ipfix", "netflow", "sflow"} {
		if s, ok := st[name]; !ok || s.Active {
			t.Errorf("%s: stato = %+v, atteso presente e non attivo", name, s)
		}
	}

	// Master switch off: tutto si ferma.
	off := DefaultConfig()
	off.Bind = "127.0.0.1"
	m.Apply(ctx, off)
	if m.Status()["syslog"].Active {
		t.Error("syslog ancora attivo dopo aver disabilitato la pipeline")
	}
}

// Riapplicare la stessa configurazione non deve ricreare i listener: il
// binding resta lo stesso.
func TestApplyIsIdempotent(t *testing.T) {
	m, _, _ := testManager(t)
	ctx := context.Background()
	cfg := enabledConfig(freePort(t))

	m.Apply(ctx, cfg)
	first := m.Status()["syslog"]
	m.Apply(ctx, cfg)
	second := m.Status()["syslog"]

	if !second.Active || first.Port != second.Port {
		t.Errorf("riapplicazione non idempotente: %+v -> %+v", first, second)
	}
}

// Cambiare porta deve fermare il vecchio listener prima di aprire il nuovo:
// altrimenti su Windows il secondo bind fallirebbe.
func TestApplyRebindsOnPortChange(t *testing.T) {
	m, _, _ := testManager(t)
	ctx := context.Background()

	p1 := freePort(t)
	m.Apply(ctx, enabledConfig(p1))
	if got := m.Status()["syslog"].Port; got != p1 {
		t.Fatalf("porta = %d, attesa %d", got, p1)
	}

	p2 := freePort(t)
	m.Apply(ctx, enabledConfig(p2))
	if got := m.Status()["syslog"].Port; got != p2 {
		t.Fatalf("porta dopo il rebind = %d, attesa %d", got, p2)
	}

	// La porta precedente deve essere stata liberata.
	c, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p1))
	if err != nil {
		t.Errorf("la porta %d non è stata liberata: %v", p1, err)
	} else {
		c.Close()
	}
}

// Un bind fallito viene riportato nello stato e non impedisce all'app di
// proseguire.
func TestApplyRecordsBindFailure(t *testing.T) {
	m, _, _ := testManager(t)
	ctx := context.Background()

	// Occupa la porta prima che il manager provi ad aprirla.
	port := freePort(t)
	busy, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skip("impossibile occupare la porta per il test")
	}
	defer busy.Close()

	m.Apply(ctx, enabledConfig(port))
	st := m.Status()["syslog"]
	if st.Active {
		t.Error("il listener risulta attivo nonostante la porta occupata")
	}
	if st.Error == "" {
		t.Error("errore di bind non riportato nello stato")
	}
	counters, _ := m.metrics.Snapshot()
	if counters["listener_bind_failed{listener=syslog}"] != 1 {
		t.Errorf("listener_bind_failed = %d, atteso 1 (%v)", counters["listener_bind_failed{listener=syslog}"], counters)
	}
}

// Il percorso completo: datagramma syslog da un exporter in inventario →
// riga in syslog_events con il tenant corretto.
func TestEndToEndSyslogIngest(t *testing.T) {
	m, obs, st := testManager(t)
	ctx := context.Background()

	if err := st.UpsertDevice(&store.Device{
		IP: "127.0.0.1", Vendor: "cisco", Tenant: "TenantA",
	}); err != nil {
		t.Fatal(err)
	}

	port := freePort(t)
	m.Apply(ctx, enabledConfig(port))
	if !m.Status()["syslog"].Active {
		t.Skip("listener non avviato (porta occupata): test saltato")
	}

	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("<134>prova ingest")); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	var tenant, message string
	for time.Now().Before(deadline) {
		obs.Sync()
		err := obs.DB.QueryRow(`SELECT tenant, message FROM syslog_events LIMIT 1`).Scan(&tenant, &message)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tenant != "TenantA" {
		t.Errorf("tenant = %q, atteso TenantA", tenant)
	}
	if message != "prova ingest" {
		t.Errorf("message = %q", message)
	}
}

// Un exporter non in inventario non deve produrre righe: finisce in quarantena.
func TestEndToEndUnknownExporterIsQuarantined(t *testing.T) {
	m, obs, _ := testManager(t)
	ctx := context.Background()

	port := freePort(t)
	m.Apply(ctx, enabledConfig(port))
	if !m.Status()["syslog"].Active {
		t.Skip("listener non avviato: test saltato")
	}

	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("<134>da un exporter sconosciuto"))

	deadline := time.Now().Add(5 * time.Second)
	var quarantined int
	for time.Now().Before(deadline) {
		obs.Sync()
		obs.DB.QueryRow(`SELECT COUNT(*) FROM quarantined_exporters`).Scan(&quarantined)
		if quarantined > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if quarantined != 1 {
		t.Fatalf("exporter in quarantena = %d, atteso 1", quarantined)
	}
	var events int
	obs.DB.QueryRow(`SELECT COUNT(*) FROM syslog_events`).Scan(&events)
	if events != 0 {
		t.Errorf("eventi scritti = %d, attesi 0 per un exporter sconosciuto", events)
	}
}

func TestShutdownStopsEverything(t *testing.T) {
	m, _, _ := testManager(t)
	ctx := context.Background()
	port := freePort(t)
	m.Apply(ctx, enabledConfig(port))

	done := make(chan struct{})
	go func() { m.Shutdown(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Shutdown non è terminato")
	}
	if m.Status()["syslog"].Active {
		t.Error("listener ancora attivo dopo lo shutdown")
	}
}
