package observability

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fortigate"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// fakeFGT avvia un FortiGate finto in TLS e ritorna la ClientFunc che punta
// a lui per qualunque IP registrato in devices.
func fakeFGT(t *testing.T, h http.HandlerFunc) ClientFunc {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return func(ip string) (*fortigate.Client, error) {
		return fortigate.New(u.Hostname(), port, "token", false), nil
	}
}

func countObservations(t *testing.T, m *Manager) (int, string) {
	t.Helper()
	m.obs.Sync()
	var n int
	var kinds string
	row := m.obs.DB.QueryRow(
		`SELECT COUNT(*), COALESCE(GROUP_CONCAT(DISTINCT kind), '') FROM api_observations`)
	if err := row.Scan(&n, &kinds); err != nil {
		t.Fatal(err)
	}
	return n, kinds
}

// Il giro di polling accoda uno snapshot per kind per ogni FortiGate con un
// target REST configurato.
func TestPollOnceEnqueuesSnapshots(t *testing.T) {
	m, _, st := testManager(t)
	if err := st.UpsertDevice(&store.Device{
		IP: "10.0.0.1", Vendor: "fortinet", Tenant: "Sede A",
	}); err != nil {
		t.Fatal(err)
	}
	m.SetClientFunc(fakeFGT(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":{"hostname":"FGT"},"version":"v7.2.5"}`))
	}))

	if n := m.PollOnce(context.Background()); n != 2 {
		t.Fatalf("snapshot accodati = %d, attesi 2", n)
	}
	n, kinds := countObservations(t, m)
	if n != 2 {
		t.Errorf("righe in api_observations = %d, attese 2", n)
	}
	if !strings.Contains(kinds, "system_status") || !strings.Contains(kinds, "interfaces") {
		t.Errorf("kind raccolti = %q", kinds)
	}
}

// Senza ClientFunc il poller è inerte: è lo stato in cui gira chi non ha
// abilitato l'integrazione REST.
func TestPollOnceInertWithoutClientFunc(t *testing.T) {
	m, _, st := testManager(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "fortinet"}); err != nil {
		t.Fatal(err)
	}
	if n := m.PollOnce(context.Background()); n != 0 {
		t.Errorf("snapshot = %d, atteso 0 senza ClientFunc", n)
	}
}

// Solo i FortiGate vengono interrogati: puntare il client REST FortiOS a uno
// switch Cisco è tempo perso e rumore nei log.
func TestPollOnceSkipsNonFortinet(t *testing.T) {
	m, _, st := testManager(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.2", Vendor: "cisco"}); err != nil {
		t.Fatal(err)
	}
	called := false
	m.SetClientFunc(func(ip string) (*fortigate.Client, error) {
		called = true
		return nil, nil
	})
	if n := m.PollOnce(context.Background()); n != 0 {
		t.Errorf("snapshot = %d, atteso 0", n)
	}
	if called {
		t.Error("ClientFunc invocata per un device non Fortinet")
	}
}

// Un device senza target REST non è un errore: si salta e si prosegue con
// gli altri.
func TestPollOnceSkipsDeviceWithoutTarget(t *testing.T) {
	m, _, st := testManager(t)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if err := st.UpsertDevice(&store.Device{IP: ip, Vendor: "fortinet"}); err != nil {
			t.Fatal(err)
		}
	}
	inner := fakeFGT(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[]}`))
	})
	m.SetClientFunc(func(ip string) (*fortigate.Client, error) {
		if ip == "10.0.0.1" {
			return nil, fmt.Errorf("nessun target configurato")
		}
		return inner(ip)
	})

	if n := m.PollOnce(context.Background()); n != 2 {
		t.Fatalf("snapshot = %d, attesi 2 (solo il secondo device)", n)
	}
	var ip string
	m.obs.Sync()
	if err := m.obs.DB.QueryRow(`SELECT DISTINCT device_ip FROM api_observations`).Scan(&ip); err != nil {
		t.Fatal(err)
	}
	if ip != "10.0.0.2" {
		t.Errorf("device_ip = %q, atteso 10.0.0.2", ip)
	}
}

// Un apparato che non risponde non deve far fallire il giro né lasciare
// righe a metà.
func TestPollOnceSurvivesUnreachableDevice(t *testing.T) {
	m, _, st := testManager(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "fortinet"}); err != nil {
		t.Fatal(err)
	}
	m.SetClientFunc(fakeFGT(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	if n := m.PollOnce(context.Background()); n != 0 {
		t.Errorf("snapshot = %d, atteso 0", n)
	}
	if n, _ := countObservations(t, m); n != 0 {
		t.Errorf("righe = %d, attese 0", n)
	}
}

// Il tenant vuoto diventa "Generale": lo scoping per tenant filtra su questo
// campo, e una stringa vuota renderebbe lo snapshot invisibile a tutti.
func TestPollOnceDefaultsTenant(t *testing.T) {
	m, _, st := testManager(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "fortinet"}); err != nil {
		t.Fatal(err)
	}
	m.SetClientFunc(fakeFGT(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[]}`))
	}))
	m.PollOnce(context.Background())

	m.obs.Sync()
	var tenant string
	if err := m.obs.DB.QueryRow(`SELECT DISTINCT tenant FROM api_observations`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if tenant != "Generale" {
		t.Errorf("tenant = %q, atteso Generale", tenant)
	}
}

// Uno snapshot enorme va troncato: finisce nel contesto dell'AI, che ha un
// budget di token da rispettare.
func TestPollOnceTruncatesLargeSnapshot(t *testing.T) {
	m, _, st := testManager(t)
	if err := st.UpsertDevice(&store.Device{IP: "10.0.0.1", Vendor: "fortinet"}); err != nil {
		t.Fatal(err)
	}
	huge := strings.Repeat("x", maxSummary*2)
	m.SetClientFunc(fakeFGT(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"results":{"blob":%q}}`, huge)
	}))
	m.PollOnce(context.Background())

	m.obs.Sync()
	rows, err := m.obs.DB.Query(`SELECT LENGTH(summary_json) FROM api_observations`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var l int
		if err := rows.Scan(&l); err != nil {
			t.Fatal(err)
		}
		if l > maxSummary {
			t.Errorf("summary_json lungo %d, massimo %d", l, maxSummary)
		}
	}
}
