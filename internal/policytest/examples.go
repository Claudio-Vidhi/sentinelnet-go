package policytest

import (
	"fmt"
	"strings"
)

var protoNamesRev = map[int]string{
	1:   "icmp",
	2:   "igmp",
	6:   "tcp",
	17:  "udp",
	47:  "gre",
	50:  "esp",
	51:  "ah",
	88:  "eigrp",
	89:  "ospf",
	103: "pim",
	132: "sctp",
}

// RuleExample represents generated example traffic and near-miss flow for a single rule.
type RuleExample struct {
	RuleID         string `json:"rule_id"`
	RuleName       string `json:"rule_name"`
	Action         string `json:"action"`
	RawText        string `json:"raw_text"`
	MatchingFlow   *Flow  `json:"matching_flow,omitempty"`
	NearMissFlow   *Flow  `json:"near_miss_flow,omitempty"`
	NearMissReason string `json:"near_miss_reason,omitempty"`
	MatchesAll     bool   `json:"matches_all"`
}

func (re RuleExample) ToMap() map[string]any {
	m := map[string]any{
		"rule_id":          re.RuleID,
		"rule_name":        re.RuleName,
		"action":           re.Action,
		"raw_text":         re.RawText,
		"matches_all":      re.MatchesAll,
		"near_miss_reason": re.NearMissReason,
	}
	if re.MatchingFlow != nil {
		m["matching_flow"] = re.MatchingFlow.ToMap()
	} else {
		m["matching_flow"] = nil
	}
	if re.NearMissFlow != nil {
		m["near_miss_flow"] = re.NearMissFlow.ToMap()
	} else {
		m["near_miss_flow"] = nil
	}
	return m
}

func scatterIntoFreeBits(cube Cube, n int) uint32 {
	free := ^cube.Mask
	out := uint32(0)
	remaining := n
	for bit := 0; bit < 32; bit++ {
		if (free & (1 << bit)) == 0 {
			continue
		}
		if (remaining & 1) != 0 {
			out |= (1 << bit)
		}
		remaining >>= 1
		if remaining == 0 {
			break
		}
	}
	return cube.Value | out
}

func pickIPInCubes(cubes []Cube, hints []string, fallback string) string {
	for _, h := range hints {
		if hInt, err := IPToInt(h); err == nil {
			for _, c := range cubes {
				if c.ContainsIP(hInt) {
					return h
				}
			}
		}
	}

	if len(cubes) == 0 {
		return fallback
	}

	first := cubes[0]
	if first.IsAny() {
		return fallback
	}
	if first.IsExact() {
		return IntToIP(first.Value)
	}

	pfx := MaskToPrefixLen(first.Mask)
	if pfx != nil {
		if *pfx >= 31 {
			return IntToIP(first.Value)
		}
		offset := uint32(10)
		if (1 << (32 - *pfx)) <= 15 {
			offset = 1
		}
		return IntToIP(first.Value + offset)
	}

	return IntToIP(scatterIntoFreeBits(first, 1))
}

func pickOutsideIP(cube Cube) string {
	if cube.IsAny() {
		return "192.0.2.1"
	}
	lsb := cube.Mask & (-cube.Mask)
	if cube.Mask == 0 {
		lsb = 1
	}
	outsideVal := cube.Value ^ lsb
	return IntToIP(outsideVal)
}

// GenerateRuleExample synthesizes a representative matching Flow and near-miss Flow for a Rule.
func GenerateRuleExample(rule Rule, hintAddresses []string) RuleExample {
	fields := rule.Fields
	if fields.Opaque {
		reason := strings.Join(rule.Unresolved, "; ")
		if reason == "" {
			reason = "rule could not be parsed: coverage unknown"
		}
		return RuleExample{
			RuleID:         rule.ID,
			RuleName:       rule.Name,
			Action:         rule.Action,
			RawText:        rule.RawText,
			MatchingFlow:   nil,
			NearMissFlow:   nil,
			NearMissReason: reason,
		}
	}

	// 1. Pick Source IP
	srcIP := pickIPInCubes(fields.SrcIPs, hintAddresses, "192.0.2.50")

	// 2. Pick Destination IP
	dstIP := pickIPInCubes(fields.DstIPs, hintAddresses, "198.51.100.20")

	// 3. Pick Protocol
	protoStr := "tcp"
	protoNum := 6
	if len(fields.Protos) > 0 {
		for p := range fields.Protos {
			protoNum = p
			if name, ok := protoNamesRev[p]; ok {
				protoStr = name
			} else {
				protoStr = fmt.Sprintf("%d", p)
			}
			break
		}
	}

	// 4. Pick Destination Port
	var dport *int
	if protoNum == 6 || protoNum == 17 {
		if fields.DstPorts != nil && len(fields.DstPorts.Intervals) > 0 {
			lo := fields.DstPorts.Intervals[0].Lo
			if lo > 0 {
				dport = &lo
			} else {
				defaultP := 80
				if protoNum == 17 {
					defaultP = 53
				}
				dport = &defaultP
			}
		} else {
			defaultP := 443
			if protoNum == 17 {
				defaultP = 53
			}
			dport = &defaultP
		}
	}

	// 5. Pick Source Port
	var sport *int
	if protoNum == 6 || protoNum == 17 {
		if fields.SrcPorts != nil && len(fields.SrcPorts.Intervals) > 0 {
			lo := fields.SrcPorts.Intervals[0].Lo
			sport = &lo
		} else {
			defaultSP := 52100
			sport = &defaultSP
		}
	}

	// 5b. Pick ICMP message type
	var icmpType *int
	if len(fields.ICMPTypes) > 0 {
		for t := range fields.ICMPTypes {
			tVal := t
			icmpType = &tVal
			break
		}
	}

	// 6. Ingress and Egress interfaces
	var ingressIntf string
	for i := range fields.IngressIntfs {
		ingressIntf = i
		break
	}
	var egressIntf string
	for i := range fields.EgressIntfs {
		egressIntf = i
		break
	}

	matchingFlow := &Flow{
		SrcIP:       srcIP,
		DstIP:       dstIP,
		Proto:       protoStr,
		SPort:       sport,
		DPort:       dport,
		IngressIntf: ingressIntf,
		EgressIntf:  egressIntf,
		Established: fields.Established,
		ICMPType:    icmpType,
	}

	// 7. Generate Near-Miss Flow
	var nearMissFlow *Flow
	var nearMissReason string

	if icmpType != nil {
		otherType := 8
		if *icmpType == 8 {
			otherType = 0
		}
		nearMissFlow = &Flow{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			Proto:       protoStr,
			SPort:       sport,
			DPort:       dport,
			IngressIntf: ingressIntf,
			EgressIntf:  egressIntf,
			Established: fields.Established,
			ICMPType:    &otherType,
		}
		nearMissReason = fmt.Sprintf("ICMP message type %d instead of %d", otherType, *icmpType)
	} else if fields.DstPorts != nil && len(fields.DstPorts.Intervals) > 0 && dport != nil {
		intervals := fields.DstPorts.Intervals
		var mutatedPort *int
		for _, iv := range intervals {
			if iv.Hi < 65535 && !fields.DstPorts.ContainsPort(iv.Hi+1) {
				p := iv.Hi + 1
				mutatedPort = &p
				break
			}
			if iv.Lo > 1 && !fields.DstPorts.ContainsPort(iv.Lo-1) {
				p := iv.Lo - 1
				mutatedPort = &p
				break
			}
		}
		if mutatedPort == nil {
			fallbackPort := 65534
			if fields.DstPorts.ContainsPort(65534) {
				fallbackPort = 1
			}
			mutatedPort = &fallbackPort
		}
		if !fields.DstPorts.ContainsPort(*mutatedPort) {
			nearMissFlow = &Flow{
				SrcIP:       srcIP,
				DstIP:       dstIP,
				Proto:       protoStr,
				SPort:       sport,
				DPort:       mutatedPort,
				IngressIntf: ingressIntf,
				EgressIntf:  egressIntf,
				Established: fields.Established,
				ICMPType:    icmpType,
			}
			nearMissReason = fmt.Sprintf("Destination port %d outside allowed ports", *mutatedPort)
		}
	} else if !allCubesAreAny(fields.DstIPs) {
		outsideDst := pickOutsideIP(fields.DstIPs[0])
		nearMissFlow = &Flow{
			SrcIP:       srcIP,
			DstIP:       outsideDst,
			Proto:       protoStr,
			SPort:       sport,
			DPort:       dport,
			IngressIntf: ingressIntf,
			EgressIntf:  egressIntf,
			Established: fields.Established,
			ICMPType:    icmpType,
		}
		nearMissReason = fmt.Sprintf("Destination IP %s outside target network", outsideDst)
	} else if !allCubesAreAny(fields.SrcIPs) {
		outsideSrc := pickOutsideIP(fields.SrcIPs[0])
		nearMissFlow = &Flow{
			SrcIP:       outsideSrc,
			DstIP:       dstIP,
			Proto:       protoStr,
			SPort:       sport,
			DPort:       dport,
			IngressIntf: ingressIntf,
			EgressIntf:  egressIntf,
			Established: fields.Established,
			ICMPType:    icmpType,
		}
		nearMissReason = fmt.Sprintf("Source IP %s outside allowed source network", outsideSrc)
	} else if len(fields.Protos) > 0 {
		mutatedProto := "udp"
		if protoNum == 17 {
			mutatedProto = "tcp"
		}
		nearMissFlow = &Flow{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			Proto:       mutatedProto,
			SPort:       sport,
			DPort:       dport,
			IngressIntf: ingressIntf,
			EgressIntf:  egressIntf,
			Established: fields.Established,
			ICMPType:    icmpType,
		}
		nearMissReason = fmt.Sprintf("Protocol %s does not match allowed protocol (%s)", mutatedProto, protoStr)
	} else if fields.Established {
		nearMissFlow = &Flow{
			SrcIP:       srcIP,
			DstIP:       dstIP,
			Proto:       protoStr,
			SPort:       sport,
			DPort:       dport,
			IngressIntf: ingressIntf,
			EgressIntf:  egressIntf,
			Established: false,
		}
		nearMissReason = "Connection is not established (SYN packet without ACK/RST)"
	} else {
		nearMissFlow = nil
		nearMissReason = "Rule matches all traffic (no near-miss)"
	}

	return RuleExample{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		Action:         rule.Action,
		RawText:        rule.RawText,
		MatchesAll:     fields.IsAnyAny(),
		MatchingFlow:   matchingFlow,
		NearMissFlow:   nearMissFlow,
		NearMissReason: nearMissReason,
	}
}

func allCubesAreAny(cubes []Cube) bool {
	if len(cubes) == 0 {
		return true
	}
	for _, c := range cubes {
		if !c.IsAny() {
			return false
		}
	}
	return true
}

func GenerateRulesetExamples(rules []Rule, hintAddresses []string) []RuleExample {
	var out []RuleExample
	for _, r := range rules {
		out = append(out, GenerateRuleExample(r, hintAddresses))
	}
	return out
}
