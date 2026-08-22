package policytest

import (
	"testing"
)

func TestPolicyExamples(t *testing.T) {
	cSrc, _ := CubeFromCIDR("192.0.2.0", 24)
	cDst, _ := CubeFromIP("198.51.100.10")
	ps443 := PortSetFromOp("eq", 443)

	rule := Rule{
		ID:     "10",
		Name:   "Allow HTTPS",
		Action: "permit",
		Fields: FieldSet{
			SrcIPs:   []Cube{cSrc},
			DstIPs:   []Cube{cDst},
			DstPorts: &ps443,
			Protos:   map[int]bool{6: true},
		},
	}

	ex := GenerateRuleExample(rule, []string{"192.0.2.77"})
	if ex.MatchingFlow == nil {
		t.Fatalf("MatchingFlow should not be nil")
	}
	if ex.MatchingFlow.SrcIP != "192.0.2.77" || ex.MatchingFlow.DstIP != "198.51.100.10" || *ex.MatchingFlow.DPort != 443 {
		t.Fatalf("MatchingFlow mismatch: %v", ex.MatchingFlow)
	}

	if ex.NearMissFlow == nil {
		t.Fatalf("NearMissFlow should not be nil")
	}
	if *ex.NearMissFlow.DPort == 443 {
		t.Fatalf("NearMissFlow should mutate destination port, got: %d", *ex.NearMissFlow.DPort)
	}
	if ex.MatchesAll {
		t.Fatalf("Rule is not matches_all")
	}

	// Any-any rule
	ruleAny := Rule{
		ID:     "99",
		Action: "permit",
		Fields: FieldSet{
			SrcIPs: []Cube{CubeAny()},
			DstIPs: []Cube{CubeAny()},
		},
	}
	exAny := GenerateRuleExample(ruleAny, nil)
	if !exAny.MatchesAll {
		t.Fatalf("ruleAny should have matches_all true")
	}
	if exAny.NearMissFlow != nil {
		t.Fatalf("ruleAny should not have near_miss_flow")
	}
}
