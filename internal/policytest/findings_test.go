package policytest

import (
	"testing"
)

func TestPolicyFindings(t *testing.T) {
	cBroad, _ := CubeFromCIDR("192.0.2.0", 24)
	cNarrow, _ := CubeFromIP("192.0.2.50")

	ruleBroad := Rule{
		ID:     "10",
		Action: "deny",
		Fields: FieldSet{
			SrcIPs: []Cube{cBroad},
			DstIPs: []Cube{CubeAny()},
		},
	}
	ruleNarrow := Rule{
		ID:     "20",
		Action: "permit",
		Fields: FieldSet{
			SrcIPs: []Cube{cNarrow},
			DstIPs: []Cube{CubeAny()},
		},
	}

	rs := &RuleSet{Name: "TEST_ACL", Rules: []Rule{ruleBroad, ruleNarrow}}
	findings := FindRulesetDefects(rs)

	var shadowed []Finding
	for _, f := range findings {
		if f.Key == "shadowed" {
			shadowed = append(shadowed, f)
		}
	}
	if len(shadowed) != 1 || shadowed[0].RuleID != "20" || shadowed[0].Params["shadowed_by"] != "10" {
		t.Fatalf("Shadowed finding mismatch: %v", shadowed)
	}

	// Unreachable rule after any-any
	ruleAny := Rule{
		ID:     "10",
		Action: "deny",
		Fields: FieldSet{
			SrcIPs: []Cube{CubeAny()},
			DstIPs: []Cube{CubeAny()},
		},
	}
	ruleNext := Rule{
		ID:     "20",
		Action: "permit",
		Fields: FieldSet{
			SrcIPs: []Cube{cNarrow},
			DstIPs: []Cube{CubeAny()},
		},
	}
	rsUnreach := &RuleSet{Name: "TEST_ACL", Rules: []Rule{ruleAny, ruleNext}}
	findingsUnreach := FindRulesetDefects(rsUnreach)

	var unreach []Finding
	for _, f := range findingsUnreach {
		if f.Key == "unreachable" {
			unreach = append(unreach, f)
		}
	}
	if len(unreach) != 1 || unreach[0].RuleID != "20" {
		t.Fatalf("Unreachable finding mismatch: %v", unreach)
	}

	// Any-any permit check
	rulePermitAll := Rule{
		ID:     "99",
		Action: "permit",
		Fields: FieldSet{
			SrcIPs: []Cube{CubeAny()},
			DstIPs: []Cube{CubeAny()},
		},
	}
	rsAny := &RuleSet{Name: "OPEN_ACL", Rules: []Rule{rulePermitAll}}
	findingsAny := FindRulesetDefects(rsAny)

	var anyFindings []Finding
	for _, f := range findingsAny {
		if f.Key == "any_any" {
			anyFindings = append(anyFindings, f)
		}
	}
	if len(anyFindings) != 1 || anyFindings[0].RuleID != "99" {
		t.Fatalf("Any_any finding mismatch: %v", anyFindings)
	}

	// Route to nowhere
	cConn, _ := CubeFromCIDR("192.0.2.0", 24)
	c10, _ := CubeFromCIDR("10.0.0.0", 8)
	c172, _ := CubeFromCIDR("172.16.0.0", 16)
	rt := RouteTable{
		Routes: []Route{
			{Prefix: "192.0.2.0/24", PrefixCube: cConn, Interface: "Gi0/1", Source: "connected"},
			{Prefix: "10.0.0.0/8", PrefixCube: c10, NextHop: "192.0.2.254", Interface: "Gi0/1", Source: "static"},
			{Prefix: "172.16.0.0/16", PrefixCube: c172, NextHop: "203.0.113.50", Interface: "", Source: "static"},
		},
	}

	rFindings := FindRoutingDefects(rt)
	var nowhere []Finding
	for _, f := range rFindings {
		if f.Key == "route_to_nowhere" {
			nowhere = append(nowhere, f)
		}
	}
	if len(nowhere) != 1 || nowhere[0].Params["prefix"] != "172.16.0.0/16" || nowhere[0].Params["next_hop"] != "203.0.113.50" {
		t.Fatalf("Route_to_nowhere finding mismatch: %v", nowhere)
	}
}
