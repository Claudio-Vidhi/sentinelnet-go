package api

import (
	"path/filepath"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/topology"
)

// Riproduce il lab CML (SW1—Po10—SW2—SW3): CDP annuncia i nomi lunghi
// ("Ethernet0/1"), LLDP quelli corti ("Et0/1"). Regressione per:
//  1. falso "LAG ×2" su SW2—SW3 (porte contate due volte per la doppia forma);
//  2. vicino del Port-channel non riconosciuto quando lo switch è il target del link.
func newLabApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })

	devices := []struct{ ip, host string }{
		{"192.168.31.6", "SW1"}, {"192.168.31.7", "SW2"}, {"192.168.31.8", "SW3"},
	}
	for _, d := range devices {
		if err := st.UpsertDevice(&store.Device{IP: d.ip, Vendor: "cisco", Tenant: "test_feat", Hostname: d.host}); err != nil {
			t.Fatal(err)
		}
	}

	nb := func(local, lp, remote, rp, rip string) topology.Neighbor {
		return topology.Neighbor{LocalHost: local, LocalPort: lp, RemoteHost: remote, RemotePort: rp, RemoteIP: rip}
	}
	// SW1: CDP (nomi lunghi) + LLDP (nomi corti, come dai dati reali).
	sw1Neighbors := []topology.Neighbor{
		nb("SW1", "Ethernet0/1", "SW2", "Ethernet0/0", "192.168.31.7"),
		nb("SW1", "Ethernet0/2", "SW2", "Ethernet0/2", "192.168.31.7"),
		nb("SW1", "Et0/1", "SW2", "Et0/0", ""),
		nb("SW1", "Et0/2", "SW2", "Et0/2", ""),
	}
	sw1PCs := []topology.PortChannel{{Name: "Port-channel10", Members: []string{"Ethernet0/1", "Ethernet0/2"}}}

	sw2Neighbors := []topology.Neighbor{
		nb("SW2", "Ethernet0/1", "SW3", "Ethernet0/0", "192.168.31.8"),
		nb("SW2", "Ethernet0/0", "SW1", "Ethernet0/1", "192.168.31.6"),
		nb("SW2", "Ethernet0/2", "SW1", "Ethernet0/2", "192.168.31.6"),
		nb("SW2", "Et0/0", "SW1", "Et0/1", ""),
		nb("SW2", "Et0/2", "SW1", "Et0/2", ""),
		nb("SW2", "Et0/1", "SW3", "Et0/0", ""),
	}
	sw2PCs := []topology.PortChannel{{Name: "Port-channel10", Members: []string{"Ethernet0/0", "Ethernet0/2"}}}

	sw3Neighbors := []topology.Neighbor{
		nb("SW3", "Ethernet0/0", "SW2", "Ethernet0/1", "192.168.31.7"),
		nb("SW3", "Et0/0", "SW2", "Et0/1", ""),
	}

	if err := st.UpsertTopology("192.168.31.6", "SW1", "", "", sw1Neighbors, sw1PCs); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTopology("192.168.31.7", "SW2", "", "", sw2Neighbors, sw2PCs); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertTopology("192.168.31.8", "SW3", "", "", sw3Neighbors, nil); err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, nil)
}

func findLink(links []*Link, a, b string) *Link {
	for _, l := range links {
		if (l.Source == a && l.Target == b) || (l.Source == b && l.Target == a) {
			return l
		}
	}
	return nil
}

func TestBuildGraphDeduplicatesCDPAndLLDPPorts(t *testing.T) {
	app := newLabApp(t)
	_, links, err := app.buildGraph(nil, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 2 {
		t.Fatalf("attesi 2 link, trovati %d: %+v", len(links), links)
	}

	// SW1—SW2: vero Port-channel con 2 membri (non 4).
	l12 := findLink(links, "192.168.31.6", "192.168.31.7")
	if l12 == nil {
		t.Fatal("link SW1-SW2 mancante")
	}
	if l12.MemberCount != 2 {
		t.Errorf("SW1-SW2: attesi 2 membri, trovati %d (local=%v remote=%v)", l12.MemberCount, l12.LocalPorts, l12.RemotePorts)
	}
	if !l12.IsPortChannel || l12.PCName != "Port-channel10" {
		t.Errorf("SW1-SW2: atteso Port-channel10, trovato is_pc=%v pc_name=%q", l12.IsPortChannel, l12.PCName)
	}

	// SW2—SW3: singolo link fisico, NIENTE LAG.
	l23 := findLink(links, "192.168.31.7", "192.168.31.8")
	if l23 == nil {
		t.Fatal("link SW2-SW3 mancante")
	}
	if l23.MemberCount != 1 {
		t.Errorf("SW2-SW3: atteso 1 membro, trovati %d (local=%v remote=%v)", l23.MemberCount, l23.LocalPorts, l23.RemotePorts)
	}
	if l23.IsPortChannel {
		t.Errorf("SW2-SW3: marcato LAG ma non esiste alcun port-channel")
	}
}

func TestPortchannelNeighborRecognizedFromBothSides(t *testing.T) {
	app := newLabApp(t)
	nodes, links, err := app.buildGraph(nil, "all")
	if err != nil {
		t.Fatal(err)
	}
	nodeByID := map[string]*Node{}
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	// Stessa logica di handlePortchannels: il vicino del Po10 di SW2 deve
	// risolversi a SW1 anche se SW2 è il *target* del link.
	pcMembers := []string{"Ethernet0/0", "Ethernet0/2"} // Po10 di SW2
	rowIP := "192.168.31.7"
	var neighbors []string
	for _, l := range links {
		var otherID string
		var myPorts []string
		switch rowIP {
		case l.Source:
			otherID, myPorts = l.Target, l.LocalPorts
		case l.Target:
			otherID, myPorts = l.Source, l.RemotePorts
		default:
			continue
		}
		if portsOverlap(myPorts, pcMembers) {
			if n, ok := nodeByID[otherID]; ok {
				neighbors = appendUniq(neighbors, n.Label)
			}
		}
	}
	if len(neighbors) != 1 || neighbors[0] != "SW1" {
		t.Errorf("Po10 di SW2: atteso vicino [SW1], trovato %v", neighbors)
	}
}

func TestNormPort(t *testing.T) {
	cases := [][2]string{
		{"Ethernet0/1", "Et0/1"},
		{"GigabitEthernet1/0/24", "Gi1/0/24"},
		{"TenGigabitEthernet1/1/1", "Te1/1/1"},
		{"Port-channel10", "Po10"},
	}
	for _, c := range cases {
		if normPort(c[0]) != normPort(c[1]) {
			t.Errorf("normPort: %q e %q dovrebbero coincidere (%q vs %q)", c[0], c[1], normPort(c[0]), normPort(c[1]))
		}
	}
}
