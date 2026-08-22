package policytest

import (
	"testing"
)

func TestIOSAceParser(t *testing.T) {
	rule1 := ParseACELine("access-list 10 permit 192.0.2.50", "", "standard", nil)
	if rule1 == nil || rule1.Action != "permit" {
		t.Fatalf("ParseACELine standard failed")
	}
	if !rule1.Fields.Matches(Flow{SrcIP: "192.0.2.50", DstIP: "198.51.100.1"}) {
		t.Fatalf("rule1 should match 192.0.2.50")
	}
	if rule1.Fields.Matches(Flow{SrcIP: "192.0.2.51", DstIP: "198.51.100.1"}) {
		t.Fatalf("rule1 should not match 192.0.2.51")
	}

	rule2 := ParseACELine("10 permit tcp 192.0.2.0 0.0.0.255 host 198.51.100.10 eq 443", "", "extended", nil)
	if rule2 == nil || rule2.ID != "10" || rule2.Action != "permit" {
		t.Fatalf("ParseACELine extended failed")
	}
	if !rule2.Fields.Matches(Flow{SrcIP: "192.0.2.50", DstIP: "198.51.100.10", Proto: "tcp", DPort: intPtr(443)}) {
		t.Fatalf("rule2 should match flow")
	}
	if rule2.Fields.Matches(Flow{SrcIP: "192.0.2.50", DstIP: "198.51.100.10", Proto: "tcp", DPort: intPtr(80)}) {
		t.Fatalf("rule2 should not match wrong port")
	}

	ruleEst := ParseACELine("20 permit tcp any any established log", "", "extended", nil)
	if ruleEst == nil || !ruleEst.Fields.Established {
		t.Fatalf("established flag not parsed")
	}
	if !ruleEst.Fields.Matches(Flow{SrcIP: "192.0.2.1", DstIP: "198.51.100.1", Proto: "tcp", Established: true}) {
		t.Fatalf("ruleEst should match established")
	}
	if ruleEst.Fields.Matches(Flow{SrcIP: "192.0.2.1", DstIP: "198.51.100.1", Proto: "tcp", Established: false}) {
		t.Fatalf("ruleEst should not match non-established")
	}

	ruleRemark := ParseACELine("remark Allow web traffic", "", "extended", nil)
	if ruleRemark != nil {
		t.Fatalf("remarks should be skipped")
	}

	ruleOpaque := ParseACELine("permit ip strange syntax cannot parse ???", "", "extended", nil)
	if ruleOpaque == nil || !ruleOpaque.Fields.Opaque {
		t.Fatalf("opaque rule not marked")
	}
}

func TestIOSConfigParsing(t *testing.T) {
	sampleConfig := `
hostname switch-01
!
object-group network DMZ_SERVERS
 host 192.0.2.10
 host 192.0.2.11
!
object-group service WEB_SERVICES
 tcp eq www
 tcp eq 443
!
ip access-list extended GUEST_IN
 10 remark Drop access to DMZ
 20 deny ip any object-group DMZ_SERVERS
 30 permit ip 192.0.2.0 0.0.0.255 any
!
interface GigabitEthernet0/1
 description Ingress LAN
 ip address 192.0.2.1 255.255.255.0
 ip access-group GUEST_IN in
!
interface GigabitEthernet0/2
 description Egress WAN
 ip address 198.51.100.1 255.255.255.0
!
interface GigabitEthernet0/3
 description Down link
 shutdown
 ip address 203.0.113.1 255.255.255.0
!
ip route 0.0.0.0 0.0.0.0 198.51.100.254
ip route 10.0.0.0 255.0.0.0 198.51.100.200 5
!
router ospf 1
 network 192.0.2.0 0.0.0.255 area 0
!
`
	env := ParseIOSConfig(sampleConfig)

	if len(env.ObjectGroups["DMZ_SERVERS"].Cubes) != 2 {
		t.Fatalf("DMZ_SERVERS cubes count = %d, expected 2", len(env.ObjectGroups["DMZ_SERVERS"].Cubes))
	}

	guestACL := env.ACLs["GUEST_IN"]
	if guestACL == nil || len(guestACL.Rules) != 2 {
		t.Fatalf("GUEST_IN rules count = %v, expected 2", guestACL)
	}

	intf1 := env.Interfaces["GigabitEthernet0/1"]
	if intf1 == nil || intf1["ip"] != "192.0.2.1" || intf1["acl_in"] != "GUEST_IN" {
		t.Fatalf("GigabitEthernet0/1 interface mismatch: %v", intf1)
	}

	rt := env.RouteTable
	if !rt.DynamicRoutingPresent || len(rt.Protocols) == 0 || rt.Protocols[0] != "ospf" {
		t.Fatalf("RouteTable dynamic routing mismatch")
	}

	r10 := rt.Lookup("10.1.2.3")
	if r10 == nil || r10.Prefix != "10.0.0.0/8" || r10.Interface != "GigabitEthernet0/2" {
		t.Fatalf("RouteTable lookup 10.1.2.3 mismatch: %v", r10)
	}

	rDef := rt.Lookup("8.8.8.8")
	if rDef == nil || rDef.Prefix != "0.0.0.0/0" || rDef.Interface != "GigabitEthernet0/2" {
		t.Fatalf("RouteTable lookup default mismatch: %v", rDef)
	}
}
