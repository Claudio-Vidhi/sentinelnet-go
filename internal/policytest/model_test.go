package policytest

import (
	"testing"
)

func TestCubePrimitives(t *testing.T) {
	val, err := IPToInt("192.0.2.1")
	if err != nil || val != 0xC0000201 {
		t.Fatalf("IPToInt unexpected: val=%X, err=%v", val, err)
	}
	if ip := IntToIP(0xC0000201); ip != "192.0.2.1" {
		t.Fatalf("IntToIP unexpected: %s", ip)
	}

	pfx := MaskToPrefixLen(0xFFFFFFFF)
	if pfx == nil || *pfx != 32 {
		t.Fatalf("MaskToPrefixLen(/32) = %v", pfx)
	}
	pfx24 := MaskToPrefixLen(0xFFFFFF00)
	if pfx24 == nil || *pfx24 != 24 {
		t.Fatalf("MaskToPrefixLen(/24) = %v", pfx24)
	}
	if pfxNonContig := MaskToPrefixLen(0xFF00FF00); pfxNonContig != nil {
		t.Fatalf("MaskToPrefixLen(non-contig) should be nil, got %v", pfxNonContig)
	}

	cExact, err := CubeFromIP("192.0.2.10")
	if err != nil || !cExact.IsExact() || cExact.IsAny() {
		t.Fatalf("CubeFromIP error or bad flags: %v", err)
	}
	ip10, _ := IPToInt("192.0.2.10")
	ip11, _ := IPToInt("192.0.2.11")
	if !cExact.ContainsIP(ip10) || cExact.ContainsIP(ip11) {
		t.Fatalf("ContainsIP mismatch")
	}

	cAny := CubeAny()
	if !cAny.IsAny() || !cAny.ContainsIP(ip10) || !cAny.ContainsIP(ip11) {
		t.Fatalf("CubeAny mismatch")
	}

	c24, _ := CubeFromCIDR("192.0.2.0", 24)
	c28, _ := CubeFromCIDR("192.0.2.16", 28)
	cHost, _ := CubeFromIP("192.0.2.20")
	cOther, _ := CubeFromCIDR("198.51.100.0", 24)

	if !c24.ContainsCube(c28) || !c24.ContainsCube(cHost) || !c28.ContainsCube(cHost) {
		t.Fatalf("c24 should contain c28 and cHost")
	}
	if c28.ContainsCube(c24) || c24.ContainsCube(cOther) {
		t.Fatalf("c28 should not contain c24; c24 should not contain cOther")
	}

	if !c24.Intersects(c28) || c24.Intersects(cOther) {
		t.Fatalf("Intersects mismatch")
	}

	// Wildcard non-contiguous
	cWild, err := CubeFromWildcard("192.0.0.10", "0.0.255.0")
	if err != nil {
		t.Fatalf("CubeFromWildcard error: %v", err)
	}
	ip1_10, _ := IPToInt("192.0.1.10")
	ip200_10, _ := IPToInt("192.0.200.10")
	ip1_11, _ := IPToInt("192.0.1.11")
	if !cWild.ContainsIP(ip1_10) || !cWild.ContainsIP(ip200_10) || cWild.ContainsIP(ip1_11) {
		t.Fatalf("Wildcard containment mismatch")
	}
}

func TestPortSetPrimitives(t *testing.T) {
	ps := NewPortSet([]PortInterval{{Lo: 80, Hi: 80}, {Lo: 81, Hi: 85}, {Lo: 443, Hi: 443}, {Lo: 1, Hi: 10}})
	if len(ps.Intervals) != 3 {
		t.Fatalf("normalizeIntervals expected 3 intervals, got %d", len(ps.Intervals))
	}

	eq80 := PortSetFromOp("eq", 80)
	if !eq80.ContainsPort(80) || eq80.ContainsPort(81) {
		t.Fatalf("eq80 mismatch")
	}

	gt1024 := PortSetFromOp("gt", 1024)
	if !gt1024.ContainsPort(5000) || gt1024.ContainsPort(1024) {
		t.Fatalf("gt1024 mismatch")
	}

	lt100 := PortSetFromOp("lt", 100)
	if !lt100.ContainsPort(50) || lt100.ContainsPort(100) {
		t.Fatalf("lt100 mismatch")
	}

	neq443 := PortSetFromOp("neq", 443)
	if neq443.ContainsPort(443) || !neq443.ContainsPort(80) {
		t.Fatalf("neq443 mismatch")
	}

	psAll := PortSetAny()
	if !psAll.ContainsPortSet(eq80) || !psAll.ContainsPortSet(gt1024) {
		t.Fatalf("psAll should contain eq80 and gt1024")
	}
	if eq80.ContainsPortSet(psAll) {
		t.Fatalf("eq80 should not contain psAll")
	}
}

func TestFieldSetMatching(t *testing.T) {
	cSrc, _ := CubeFromCIDR("10.0.0.0", 24)
	cDst, _ := CubeFromIP("192.168.1.50")
	psHTTP := PortSetFromOp("eq", 80)

	fs := FieldSet{
		SrcIPs:   []Cube{cSrc},
		DstIPs:   []Cube{cDst},
		DstPorts: &psHTTP,
		Protos:   map[int]bool{6: true},
	}

	matchFlow := Flow{
		SrcIP: "10.0.0.5",
		DstIP: "192.168.1.50",
		Proto: "tcp",
		DPort: intPtr(80),
	}
	if !fs.Matches(matchFlow) {
		t.Fatalf("fs should match flow")
	}

	wrongPort := Flow{
		SrcIP: "10.0.0.5",
		DstIP: "192.168.1.50",
		Proto: "tcp",
		DPort: intPtr(443),
	}
	if fs.Matches(wrongPort) {
		t.Fatalf("fs should not match wrong port")
	}

	wrongSrc := Flow{
		SrcIP: "10.0.1.5",
		DstIP: "192.168.1.50",
		Proto: "tcp",
		DPort: intPtr(80),
	}
	if fs.Matches(wrongSrc) {
		t.Fatalf("fs should not match wrong source IP")
	}
}
