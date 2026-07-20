package mac

import "testing"

const showInterfaces = `GigabitEthernet1/0/1 is up, line protocol is up (connected)
  Hardware is Gigabit Ethernet, address is aabb.ccdd.0001 (bia aabb.ccdd.0001)
  MTU 1500 bytes, BW 1000000 Kbit/sec
GigabitEthernet1/0/2 is down, line protocol is down (notconnect)
  Hardware is Gigabit Ethernet, address is aabb.ccdd.0002 (bia aabb.ccdd.0002)
Vlan1 is administratively down, line protocol is down
  Hardware is EtherSVI, address is aabb.ccdd.00ff (bia aabb.ccdd.00ff)
`

func TestParseCLIIfMacs(t *testing.T) {
	got := ParseCLIIfMacs(showInterfaces)
	want := []IfMac{
		{Interface: "GigabitEthernet1/0/1", Mac: "aabb.ccdd.0001"},
		{Interface: "GigabitEthernet1/0/2", Mac: "aabb.ccdd.0002"},
		{Interface: "Vlan1", Mac: "aabb.ccdd.00ff"},
	}
	if len(got) != len(want) {
		t.Fatalf("entry = %d, attese %d (%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] got %+v, want %+v", i, got[i], want[i])
		}
	}
}

// Un "address is" prima di qualsiasi intestazione non deve produrre righe
// senza interfaccia.
func TestParseCLIIfMacsIgnoresAddressWithoutInterface(t *testing.T) {
	if got := ParseCLIIfMacs("  address is aabb.ccdd.0001\n"); len(got) != 0 {
		t.Fatalf("entry = %d, attese 0 (%+v)", len(got), got)
	}
}

func TestParseCLIIfMacsEmpty(t *testing.T) {
	if got := ParseCLIIfMacs(""); len(got) != 0 {
		t.Fatalf("entry = %d, attese 0", len(got))
	}
}
