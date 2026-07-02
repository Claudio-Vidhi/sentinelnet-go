package topology

import "testing"

// Output reale IOS "show lldp neighbors detail": la porta locale sta nella
// riga "Local Intf" e i blocchi sono separati da trattini. Regressione per il
// parser che divideva i blocchi proprio su "Local Intf" perdendo la porta.
const lldpDetail = `------------------------------------------------
Local Intf: Et0/2
Chassis id: aabb.cc00.1000
Port id: Et0/2
Port Description: Ethernet0/2
System Name: SW1

System Description:
Cisco IOS Software, Linux Software (I86BI_LINUXL2-ADVENTERPRISEK9-M)

Time remaining: 96 seconds
Management Addresses:
    IP: 192.168.31.6
------------------------------------------------
Local Intf: Et0/0
Chassis id: aabb.cc00.1000
Port id: Et0/1
Port Description: Ethernet0/1
System Name: SW1

Management Addresses:
    IP: 192.168.31.6

Total entries displayed: 2
`

func TestParseLLDPNeighborsExtractsLocalPort(t *testing.T) {
	got := ParseLLDPNeighbors("SW2", lldpDetail)
	if len(got) != 2 {
		t.Fatalf("attesi 2 vicini, trovati %d: %+v", len(got), got)
	}
	want := []Neighbor{
		{LocalHost: "SW2", LocalPort: "Et0/2", RemoteHost: "SW1", RemotePort: "Et0/2", RemoteIP: "192.168.31.6"},
		{LocalHost: "SW2", LocalPort: "Et0/0", RemoteHost: "SW1", RemotePort: "Et0/1", RemoteIP: "192.168.31.6"},
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("vicino %d: atteso %+v, trovato %+v", i, w, got[i])
		}
	}
}
