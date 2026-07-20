package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func flowgraphApp(t *testing.T) (*App, *store.Store, *obsstore.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "main.db"))
	if err != nil {
		t.Fatal(err)
	}
	obs, err := obsstore.Open(filepath.Join(dir, "obs.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { obs.Close(); st.DB.Close() })

	app := NewApp(nil, st, nil, nil)
	app.EnableObservability(obs)
	return app, st, obs
}

// seedFlow inserisce un flusso aggregato nella finestra corrente.
func seedFlow(t *testing.T, obs *obsstore.Store, tenant, src, dst string, proto, port int, bytes int64) {
	t.Helper()
	window := time.Now().Unix() - 60
	obs.EnqueueWrite(`INSERT INTO flow_aggregates
		(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
		VALUES (?,?,?,?,?,?,?,?,1)`,
		window-window%60, tenant, src, dst, proto, port, bytes, 1)
}

func getFlowGraph(t *testing.T, app *App, role string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/observability/flowgraph?window=15m", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey,
		&auth.Claims{Username: "u", Role: role}))
	rec := httptest.NewRecorder()
	app.handleObsFlowGraph(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSyntheticVLANIsDeterministicAndInRange(t *testing.T) {
	for _, tenant := range []string{"", "Generale", "SedeMilano", "tenant-x"} {
		v1, v2 := syntheticVLAN(tenant), syntheticVLAN(tenant)
		if v1 != v2 {
			t.Errorf("%q: non deterministica (%d != %d)", tenant, v1, v2)
		}
		if v1 < 100 || v1 > 999 {
			t.Errorf("%q: VLAN %d fuori dall'intervallo 100-999", tenant, v1)
		}
	}
	if syntheticVLAN("A") == syntheticVLAN("B") {
		t.Error("tenant diversi producono la stessa VLAN sintetica")
	}
}

func TestProtoLabel(t *testing.T) {
	six, udp, odd, zero := 6, 17, 47, 0
	cases := []struct {
		in   *int
		want string
	}{
		{&six, "tcp"}, {&udp, "udp"}, {&odd, "47"},
		{nil, "?"}, {&zero, "?"},
	}
	for _, c := range cases {
		if got := protoLabel(c.in); got != c.want {
			t.Errorf("protoLabel(%v) = %q, atteso %q", c.in, got, c.want)
		}
	}
}

// Senza binding ARP la VLAN è sintetica e dichiarata come tale: la UI deve
// poter distinguere un dato reale da un ripiego.
func TestFlowGraphFallsBackToSyntheticVLAN(t *testing.T) {
	app, _, obs := flowgraphApp(t)
	seedFlow(t, obs, "TenantA", "10.0.0.1", "10.0.0.2", 6, 443, 1000)
	obs.Sync()

	out := getFlowGraph(t, app, "admin")
	nodes := out["nodes"].([]any)
	if len(nodes) != 2 {
		t.Fatalf("nodi = %d, attesi 2", len(nodes))
	}
	for _, n := range nodes {
		node := n.(map[string]any)
		if node["vlan_real"].(bool) {
			t.Errorf("nodo %v: vlan_real=true senza alcun binding ARP", node["id"])
		}
		if v := int(node["vlan"].(float64)); v != syntheticVLAN("TenantA") {
			t.Errorf("nodo %v: vlan %d, attesa quella sintetica %d", node["id"], v, syntheticVLAN("TenantA"))
		}
	}
}

// Con un binding ARP noto si usa la VLAN reale e la si dichiara tale.
func TestFlowGraphUsesRealVLANWhenKnown(t *testing.T) {
	app, st, obs := flowgraphApp(t)
	seedFlow(t, obs, "TenantA", "10.0.0.1", "10.0.0.2", 6, 443, 1000)
	obs.Sync()

	if _, err := st.RecordARPEntries(
		[]store.ARPInput{{MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.1", VLAN: "42"}},
		"10.0.0.254", "GW", "switch", "TenantA", ""); err != nil {
		t.Fatal(err)
	}

	out := getFlowGraph(t, app, "admin")
	byID := map[string]map[string]any{}
	for _, n := range out["nodes"].([]any) {
		node := n.(map[string]any)
		byID[node["id"].(string)] = node
	}
	if got := byID["10.0.0.1"]; !got["vlan_real"].(bool) || int(got["vlan"].(float64)) != 42 {
		t.Errorf("10.0.0.1: vlan=%v real=%v, attesi 42/true", got["vlan"], got["vlan_real"])
	}
	// L'altro nodo non ha binding: resta sintetico.
	if got := byID["10.0.0.2"]; got["vlan_real"].(bool) {
		t.Error("10.0.0.2: vlan_real=true senza binding")
	}
}

// Stesso IP in due tenant diversi (RFC1918 dietro NAT): la VLAN di un tenant
// non deve comparire nel grafo dell'altro.
func TestFlowGraphVLANLookupIsTenantScoped(t *testing.T) {
	app, st, obs := flowgraphApp(t)

	// Il flusso appartiene a TenantA; il binding ARP con VLAN 999 è di TenantB.
	seedFlow(t, obs, "TenantA", "192.168.1.50", "192.168.1.1", 6, 443, 1000)
	obs.Sync()
	if _, err := st.RecordARPEntries(
		[]store.ARPInput{{MAC: "aa:bb:cc:dd:ee:02", IP: "192.168.1.50", VLAN: "999"}},
		"192.168.2.254", "GW-B", "switch", "TenantB", ""); err != nil {
		t.Fatal(err)
	}

	out := getFlowGraph(t, app, "admin")
	for _, n := range out["nodes"].([]any) {
		node := n.(map[string]any)
		if node["id"] == "192.168.1.50" {
			if node["vlan_real"].(bool) || int(node["vlan"].(float64)) == 999 {
				t.Fatalf("FUGA FRA TENANT: la VLAN di TenantB è comparsa nel grafo di TenantA (%v)", node)
			}
		}
	}
}

// I byte di un nodo sommano il traffico in cui compare sia come sorgente sia
// come destinazione: un host solo-destinazione non deve restare a zero.
func TestFlowGraphNodeBytesCountBothDirections(t *testing.T) {
	app, _, obs := flowgraphApp(t)
	seedFlow(t, obs, "T", "10.0.0.1", "10.0.0.9", 6, 443, 500)
	seedFlow(t, obs, "T", "10.0.0.2", "10.0.0.9", 6, 443, 300)
	obs.Sync()

	out := getFlowGraph(t, app, "admin")
	for _, n := range out["nodes"].([]any) {
		node := n.(map[string]any)
		if node["id"] == "10.0.0.9" {
			if got := int64(node["bytes"].(float64)); got != 800 {
				t.Errorf("byte del nodo solo-destinazione = %d, attesi 800", got)
			}
			return
		}
	}
	t.Error("nodo solo-destinazione assente dal grafo")
}

func TestFlowGraphKPIAndProtocols(t *testing.T) {
	app, _, obs := flowgraphApp(t)
	seedFlow(t, obs, "T", "10.0.0.1", "10.0.0.2", 6, 443, 900)
	seedFlow(t, obs, "T", "10.0.0.3", "10.0.0.4", 17, 53, 100)
	obs.Sync()

	out := getFlowGraph(t, app, "admin")
	kpi := out["kpi"].(map[string]any)
	if int(kpi["talkers"].(float64)) != 4 {
		t.Errorf("talkers = %v, attesi 4", kpi["talkers"])
	}
	if kpi["throughput_bps"].(float64) <= 0 {
		t.Errorf("throughput = %v, atteso > 0", kpi["throughput_bps"])
	}
	top := kpi["top_path"].(map[string]any)
	if top["src"] != "10.0.0.1" {
		t.Errorf("top_path.src = %v, atteso 10.0.0.1 (il flusso più consistente)", top["src"])
	}
	protos := out["protocols"].([]any)
	if len(protos) != 2 {
		t.Fatalf("protocolli = %d, attesi 2", len(protos))
	}
	if protos[0].(map[string]any)["proto"] != "tcp" {
		t.Errorf("primo protocollo = %v, atteso tcp (rate maggiore)", protos[0])
	}
}

// Un utente ristretto a un tenant non deve vedere i flussi di un altro.
func TestFlowGraphIsTenantScoped(t *testing.T) {
	app, st, obs := flowgraphApp(t)
	seedFlow(t, obs, "TenantA", "10.0.0.1", "10.0.0.2", 6, 443, 1000)
	seedFlow(t, obs, "TenantB", "10.9.9.1", "10.9.9.2", 6, 443, 5000)
	obs.Sync()

	if err := st.CreateTenant("TenantA", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser("ristretto", "x", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserTenants("ristretto", []string{"TenantA"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/observability/flowgraph?window=15m", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey,
		&auth.Claims{Username: "ristretto", Role: "viewer"}))
	rec := httptest.NewRecorder()
	app.handleObsFlowGraph(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)

	for _, n := range out["nodes"].([]any) {
		if id := n.(map[string]any)["id"].(string); id == "10.9.9.1" || id == "10.9.9.2" {
			t.Errorf("nodo %q di TenantB visibile a un utente ristretto a TenantA", id)
		}
	}
}

func TestFlowGraphRejectsBadWindow(t *testing.T) {
	app, _, _ := flowgraphApp(t)
	req := httptest.NewRequest("GET", "/api/observability/flowgraph?window=99y", nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey,
		&auth.Claims{Username: "u", Role: "admin"}))
	rec := httptest.NewRecorder()
	app.handleObsFlowGraph(rec, req)
	if rec.Code != 400 {
		t.Errorf("status %d, atteso 400 per una finestra non valida", rec.Code)
	}
}
