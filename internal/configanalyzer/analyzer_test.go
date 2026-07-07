package configanalyzer

import "testing"

const switchConfig = `hostname SW1
!
vlan 10
 name USERS
!
vlan 20
 name VOICE
!
vlan 999
 name UNUSED
!
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
!
interface GigabitEthernet0/1
 description Uplink
 switchport mode trunk
 switchport trunk allowed vlan 10,20
!
interface GigabitEthernet0/2
 description PC
 switchport mode access
 switchport access vlan 10
 switchport voice vlan 20
 ip access-group 100 in
!
interface GigabitEthernet0/3
 switchport access vlan 30
!
access-list 100 permit ip any any
access-list 101 deny ip any any
!
`

func vlanByID(a Analysis, id string) *Vlan {
	for i := range a.Vlans {
		if a.Vlans[i].ID == id {
			return &a.Vlans[i]
		}
	}
	return nil
}

func TestAnalyzeSwitchConfig(t *testing.T) {
	a := AnalyzeConfig(switchConfig)

	// VLAN: solo 10, 20, 999 (30 e' usata ma non definita/VTP).
	if len(a.Vlans) != 3 {
		t.Fatalf("vlans attese 3, ottenute %d: %+v", len(a.Vlans), a.Vlans)
	}
	if v := vlanByID(a, "10"); v == nil {
		t.Fatal("vlan 10 mancante")
	} else {
		if v.Name != "USERS" {
			t.Errorf("vlan10 name = %q, atteso USERS", v.Name)
		}
		if v.SVI == nil || v.SVI.IP != "10.1.10.1/24" {
			t.Errorf("vlan10 svi = %+v, atteso 10.1.10.1/24", v.SVI)
		}
		if len(v.AccessIfaces) != 1 || v.AccessIfaces[0] != "GigabitEthernet0/2" {
			t.Errorf("vlan10 access = %v", v.AccessIfaces)
		}
		if len(v.TrunkIfaces) != 1 || v.TrunkIfaces[0] != "GigabitEthernet0/1" {
			t.Errorf("vlan10 trunk = %v", v.TrunkIfaces)
		}
	}
	if v := vlanByID(a, "20"); v == nil || len(v.AccessIfaces) != 0 || len(v.TrunkIfaces) != 1 {
		t.Errorf("vlan20 inatteso: %+v", v)
	}

	// Interfacce: 4.
	if len(a.Interfaces) != 4 {
		t.Errorf("interfacce attese 4, ottenute %d", len(a.Interfaces))
	}

	// ACL: 100 (extended, applicata), 101 (inutilizzata).
	if len(a.Acls) != 2 {
		t.Fatalf("acl attese 2, ottenute %d", len(a.Acls))
	}
	if a.Acls[0].Name != "100" || a.Acls[0].Kind != "extended" {
		t.Errorf("acl100 = %+v", a.Acls[0])
	}
	if len(a.Acls[0].Applied) != 1 || a.Acls[0].Applied[0].Target != "GigabitEthernet0/2" || a.Acls[0].Applied[0].Direction != "in" {
		t.Errorf("acl100 applied = %+v", a.Acls[0].Applied)
	}

	// Validazione.
	if len(a.Validation.UnusedAcls) != 1 || a.Validation.UnusedAcls[0] != "101" {
		t.Errorf("unused_acls = %v", a.Validation.UnusedAcls)
	}
	if len(a.Validation.UnusedVlans) != 1 || a.Validation.UnusedVlans[0] != "999" {
		t.Errorf("unused_vlans = %v", a.Validation.UnusedVlans)
	}
	if len(a.Validation.UndefinedVlans) != 1 || a.Validation.UndefinedVlans[0].Vlan != "30" {
		t.Errorf("undefined_vlans = %+v", a.Validation.UndefinedVlans)
	}
	if a.Validation.UndefinedVlans[0].ReferencedIn != "GigabitEthernet0/3 (access)" {
		t.Errorf("undefined_vlans ref = %q", a.Validation.UndefinedVlans[0].ReferencedIn)
	}
	if len(a.Validation.MissingAcls) != 0 {
		t.Errorf("missing_acls atteso vuoto: %+v", a.Validation.MissingAcls)
	}
}

const routerConfig = `hostname R1
!
ip route 0.0.0.0 0.0.0.0 192.0.2.1 name DEFAULT
ip route vrf CUST 10.0.0.0 255.0.0.0 10.9.9.9 200
!
router ospf 1
 network 10.1.0.0 0.0.0.255 area 0
 distribute-list 10 in
!
interface GigabitEthernet0/0
 ip address 203.0.113.2 255.255.255.252
!
`

func TestAnalyzeRouterConfig(t *testing.T) {
	a := AnalyzeConfig(routerConfig)

	if len(a.Routing.Static) != 2 {
		t.Fatalf("rotte statiche attese 2, ottenute %d", len(a.Routing.Static))
	}
	r0 := a.Routing.Static[0]
	if r0.Prefix != "0.0.0.0/0" || r0.NextHop != "192.0.2.1" || r0.Name != "DEFAULT" || r0.AD != nil {
		t.Errorf("route0 = %+v", r0)
	}
	r1 := a.Routing.Static[1]
	if r1.Prefix != "10.0.0.0/8" || r1.VRF != "CUST" || r1.AD == nil || *r1.AD != "200" {
		t.Errorf("route1 = %+v", r1)
	}

	if len(a.Routing.Protocols) != 1 || a.Routing.Protocols[0].Proto != "ospf" || a.Routing.Protocols[0].ID != "1" {
		t.Errorf("protocols = %+v", a.Routing.Protocols)
	}

	// distribute-list 10 -> ACL referenziata dal routing ma non definita.
	if len(a.Validation.RouteAclRefs) != 1 || a.Validation.RouteAclRefs[0].Acl != "10" {
		t.Errorf("route_acl_refs = %+v", a.Validation.RouteAclRefs)
	}
	if a.Validation.RouteAclRefs[0].Context != "distribute-list in router ospf 1" {
		t.Errorf("route_acl_refs context = %q", a.Validation.RouteAclRefs[0].Context)
	}
	if len(a.Validation.MissingAcls) != 1 || a.Validation.MissingAcls[0].Name != "10" {
		t.Errorf("missing_acls = %+v", a.Validation.MissingAcls)
	}

	// L'interfaccia routed espone il CIDR.
	if len(a.Interfaces) != 1 || a.Interfaces[0].IP != "203.0.113.2/30" || a.Interfaces[0].Mode != "routed" {
		t.Errorf("iface = %+v", a.Interfaces)
	}

	if HostnameFromConfig(routerConfig) != "R1" {
		t.Errorf("hostname = %q", HostnameFromConfig(routerConfig))
	}
}

func TestParseVTPStatusAndShowVlan(t *testing.T) {
	content := switchConfig + `
--- SHOW VLAN ---
1    default                          active
50   SERVERS                          active
!
--- SHOW VTP STATUS ---
VTP Operating Mode              : Server
VTP Domain Name                 : ACME-DOM
`
	vtp := ParseVTPStatus(content)
	if vtp.Mode != "server" || vtp.Domain != "ACME-DOM" {
		t.Errorf("vtp = %+v", vtp)
	}
	vv := ParseShowVlan(content)
	if vv["50"] != "SERVERS" || vv["1"] != "default" {
		t.Errorf("show vlan = %+v", vv)
	}
}
