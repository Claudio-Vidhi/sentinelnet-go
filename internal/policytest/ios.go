package policytest

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	reNumberedACL = regexp.MustCompile(`(?i)^access-list\s+(\d+)\s+(.*)$`)
	reSeqLine     = regexp.MustCompile(`^(\d+)\s+(.*)$`)
)

func isIP(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// IOSObjectGroup represents an object-group network/service/port in Cisco IOS.
type IOSObjectGroup struct {
	Name      string
	Kind      string // network | service | port
	Cubes     []Cube
	Ports     []PortInterval
	GroupRefs []string
}

func parseObjectGroups(lines []string) map[string]IOSObjectGroup {
	groups := make(map[string]IOSObjectGroup)
	var current *IOSObjectGroup

	for _, raw := range lines {
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "!") {
			if current != nil {
				groups[current.Name] = *current
				current = nil
			}
			continue
		}

		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		low := strings.ToLower(s)

		if indent == 0 && !strings.HasPrefix(low, "object-group ") {
			if current != nil {
				groups[current.Name] = *current
				current = nil
			}
			continue
		}

		if strings.HasPrefix(low, "object-group ") {
			if current != nil {
				groups[current.Name] = *current
				current = nil
			}
			toks := strings.Fields(s)
			if len(toks) >= 3 {
				kind := strings.ToLower(toks[1])
				name := toks[2]
				current = &IOSObjectGroup{Name: name, Kind: kind}
			}
			continue
		}

		if current == nil {
			continue
		}

		toks := strings.Fields(s)
		if len(toks) == 0 {
			continue
		}

		if current.Kind == "network" {
			if strings.ToLower(toks[0]) == "host" && len(toks) >= 2 && isIP(toks[1]) {
				if c, err := CubeFromIP(toks[1]); err == nil {
					current.Cubes = append(current.Cubes, c)
				}
			} else if strings.ToLower(toks[0]) == "group-object" && len(toks) >= 2 {
				current.GroupRefs = append(current.GroupRefs, toks[1])
			} else if len(toks) >= 2 && isIP(toks[0]) && isIP(toks[1]) {
				ipS, maskS := toks[0], toks[1]
				mInt, err := IPToInt(maskS)
				if err == nil {
					if (mInt&0x80000000) != 0 && MaskToPrefixLen(mInt) != nil {
						if c, err := CubeFromNetmask(ipS, maskS); err == nil {
							current.Cubes = append(current.Cubes, c)
						}
					} else {
						if c, err := CubeFromWildcard(ipS, maskS); err == nil {
							current.Cubes = append(current.Cubes, c)
						}
					}
				}
			} else if len(toks) >= 1 && isIP(toks[0]) {
				if c, err := CubeFromIP(toks[0]); err == nil {
					current.Cubes = append(current.Cubes, c)
				}
			}
		} else if current.Kind == "service" || current.Kind == "port" {
			if strings.ToLower(toks[0]) == "group-object" && len(toks) >= 2 {
				current.GroupRefs = append(current.GroupRefs, toks[1])
			} else {
				for idx, t := range toks {
					tLow := strings.ToLower(t)
					if tLow == "eq" && idx+1 < len(toks) {
						if pval := ParsePortVal(toks[idx+1]); pval != nil {
							current.Ports = append(current.Ports, PortInterval{Lo: *pval, Hi: *pval})
						}
					} else if tLow == "range" && idx+2 < len(toks) {
						p1 := ParsePortVal(toks[idx+1])
						p2 := ParsePortVal(toks[idx+2])
						if p1 != nil && p2 != nil {
							lo, hi := *p1, *p2
							if lo > hi {
								lo, hi = hi, lo
							}
							current.Ports = append(current.Ports, PortInterval{Lo: lo, Hi: hi})
						}
					} else if tLow == "gt" && idx+1 < len(toks) {
						if pval := ParsePortVal(toks[idx+1]); pval != nil && *pval < 65535 {
							current.Ports = append(current.Ports, PortInterval{Lo: *pval + 1, Hi: 65535})
						}
					} else if tLow == "lt" && idx+1 < len(toks) {
						if pval := ParsePortVal(toks[idx+1]); pval != nil && *pval > 1 {
							current.Ports = append(current.Ports, PortInterval{Lo: 1, Hi: *pval - 1})
						}
					}
				}
			}
		}
	}
	if current != nil {
		groups[current.Name] = *current
	}

	// Resolve nested references
	resolved := make(map[string]IOSObjectGroup)
	for name, grp := range groups {
		allCubes := append([]Cube{}, grp.Cubes...)
		allPorts := append([]PortInterval{}, grp.Ports...)
		seenRefs := map[string]bool{name: true}
		queue := append([]string{}, grp.GroupRefs...)

		for len(queue) > 0 {
			ref := queue[0]
			queue = queue[1:]
			if seenRefs[ref] {
				continue
			}
			sub, ok := groups[ref]
			if !ok {
				continue
			}
			seenRefs[ref] = true
			allCubes = append(allCubes, sub.Cubes...)
			allPorts = append(allPorts, sub.Ports...)
			queue = append(queue, sub.GroupRefs...)
		}

		resolved[name] = IOSObjectGroup{
			Name:      name,
			Kind:      grp.Kind,
			Cubes:     allCubes,
			Ports:     allPorts,
			GroupRefs: grp.GroupRefs,
		}
	}

	return resolved
}

func consumeIPSpec(
	toks []string,
	idx int,
	objGroups map[string]IOSObjectGroup,
	unresolved *[]string,
) ([]Cube, int) {
	if idx >= len(toks) {
		return nil, idx
	}

	tok := strings.ToLower(toks[idx])
	if tok == "any" || tok == "any4" {
		return []Cube{CubeAny()}, idx + 1
	}

	if tok == "host" {
		if idx+1 < len(toks) && isIP(toks[idx+1]) {
			if c, err := CubeFromIP(toks[idx+1]); err == nil {
				return []Cube{c}, idx + 2
			}
		}
		return nil, idx
	}

	if tok == "object-group" {
		if idx+1 < len(toks) {
			gname := toks[idx+1]
			if grp, ok := objGroups[gname]; ok && len(grp.Cubes) > 0 {
				return append([]Cube{}, grp.Cubes...), idx + 2
			}
			*unresolved = append(*unresolved, fmt.Sprintf("object-group '%s' not found or empty", gname))
			return []Cube{CubeAny()}, idx + 2
		}
		return nil, idx
	}

	if isIP(toks[idx]) {
		ipS := toks[idx]
		if idx+1 < len(toks) && isIP(toks[idx+1]) {
			wildS := toks[idx+1]
			if c, err := CubeFromWildcard(ipS, wildS); err == nil {
				return []Cube{c}, idx + 2
			}
		}
		if c, err := CubeFromIP(ipS); err == nil {
			return []Cube{c}, idx + 1
		}
	}

	return nil, idx
}

func consumePortSpec(
	toks []string,
	idx int,
	objGroups map[string]IOSObjectGroup,
	unresolved *[]string,
) (*PortSet, int) {
	if idx >= len(toks) {
		return nil, idx
	}

	tok := strings.ToLower(toks[idx])
	if tok == "eq" && idx+1 < len(toks) {
		if p := ParsePortVal(toks[idx+1]); p != nil {
			ps := PortSetFromOp("eq", *p)
			return &ps, idx + 2
		}
		return nil, idx + 2
	}

	if tok == "gt" && idx+1 < len(toks) {
		if p := ParsePortVal(toks[idx+1]); p != nil {
			ps := PortSetFromOp("gt", *p)
			return &ps, idx + 2
		}
		return nil, idx + 2
	}

	if tok == "lt" && idx+1 < len(toks) {
		if p := ParsePortVal(toks[idx+1]); p != nil {
			ps := PortSetFromOp("lt", *p)
			return &ps, idx + 2
		}
		return nil, idx + 2
	}

	if tok == "neq" && idx+1 < len(toks) {
		if p := ParsePortVal(toks[idx+1]); p != nil {
			ps := PortSetFromOp("neq", *p)
			return &ps, idx + 2
		}
		return nil, idx + 2
	}

	if tok == "range" && idx+2 < len(toks) {
		p1 := ParsePortVal(toks[idx+1])
		p2 := ParsePortVal(toks[idx+2])
		if p1 != nil && p2 != nil {
			ps := PortSetFromOp("range", *p1, *p2)
			return &ps, idx + 3
		}
		return nil, idx + 3
	}

	if tok == "object-group" && idx+1 < len(toks) {
		gname := toks[idx+1]
		if grp, ok := objGroups[gname]; ok {
			if grp.Kind == "service" || grp.Kind == "port" || len(grp.Ports) > 0 {
				ps := NewPortSet(grp.Ports)
				return &ps, idx + 2
			}
		}
		return nil, idx
	}

	return nil, idx
}

var (
	tcpFlagNames        = map[string]bool{"ack": true, "fin": true, "psh": true, "rst": true, "syn": true, "urg": true, "match-all": true, "match-any": true}
	qualifiersWithValue = map[string]bool{"precedence": true, "tos": true, "dscp": true, "time-range": true, "option": true}
	qualifiersIgnored   = map[string]bool{"log": true, "log-input": true}
)

func consumeTrailingQualifiers(
	toks []string,
	idx int,
	protoTok string,
) (bool, map[int]bool, []string) {
	established := false
	var icmpTypes map[int]bool
	var narrowing []string
	isICMP := protoTok == "icmp" || protoTok == "1"

	for idx < len(toks) {
		tok := toks[idx]
		low := strings.ToLower(tok)
		idx++

		if low == "established" {
			established = true
		} else if qualifiersIgnored[low] {
			// ignore
		} else if qualifiersWithValue[low] {
			narrowing = append(narrowing, low)
			idx++ // skip keyword value
		} else if low == "fragments" {
			narrowing = append(narrowing, low)
		} else if tcpFlagNames[low] {
			narrowing = append(narrowing, low)
		} else if isICMP {
			if tNum, ok := ICMPTypeNames[low]; ok {
				icmpTypes = map[int]bool{tNum: true}
			} else if tNum, ok := ICMPCodeNames[low]; ok {
				icmpTypes = map[int]bool{tNum: true}
				narrowing = append(narrowing, low)
			} else if n, err := strconv.Atoi(low); err == nil {
				icmpTypes = map[int]bool{n: true}
				if idx < len(toks) {
					if _, err := strconv.Atoi(toks[idx]); err == nil {
						narrowing = append(narrowing, "icmp code "+toks[idx])
						idx++
					}
				}
			} else {
				narrowing = append(narrowing, low)
			}
		} else {
			narrowing = append(narrowing, low)
		}
	}

	return established, icmpTypes, narrowing
}

func staticRouteDistance(tail []string) int {
	keywordsWithValue := map[string]bool{"name": true, "tag": true, "track": true, "metric": true}
	idx := 0
	for idx < len(tail) {
		tok := strings.ToLower(tail[idx])
		if keywordsWithValue[tok] {
			idx += 2
			continue
		}
		if n, err := strconv.Atoi(tail[idx]); err == nil && n >= 1 && n <= 255 {
			return n
		}
		idx++
	}
	return 1
}

func opaqueRule(ruleID, action, rawLine, reason string) Rule {
	return Rule{
		ID:         ruleID,
		Action:     action,
		Fields:     FieldSet{Opaque: true},
		RawText:    rawLine,
		Unresolved: []string{fmt.Sprintf("ACE not parsed: %s", reason)},
	}
}

// ParseACELine parses a single Cisco IOS ACE line into a Rule object.
func ParseACELine(
	rawLine string,
	seq string,
	kind string,
	objGroups map[string]IOSObjectGroup,
) *Rule {
	s := strings.TrimSpace(rawLine)
	if s == "" || strings.HasPrefix(s, "!") {
		return nil
	}

	groups := objGroups
	if groups == nil {
		groups = make(map[string]IOSObjectGroup)
	}
	var unresolved []string
	ruleID := seq

	// Check access-list <num>
	if mNum := reNumberedACL.FindStringSubmatch(s); len(mNum) == 3 {
		num := mNum[1]
		rest := strings.TrimSpace(mNum[2])
		n, _ := strconv.Atoi(num)
		if (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999) {
			kind = "standard"
		} else {
			kind = "extended"
		}
		if ruleID == "" {
			ruleID = num
		}
		s = rest
	} else if mSeq := reSeqLine.FindStringSubmatch(s); len(mSeq) == 3 {
		ruleID = mSeq[1]
		s = strings.TrimSpace(mSeq[2])
	}

	low := strings.ToLower(s)
	if strings.HasPrefix(low, "remark ") || low == "remark" {
		return nil
	}

	toks := strings.Fields(s)
	if len(toks) == 0 {
		return nil
	}

	actionTok := strings.ToLower(toks[0])
	if actionTok != "permit" && actionTok != "deny" {
		r := opaqueRule(ruleID, "unknown", rawLine, "Unrecognized ACE action: "+actionTok)
		return &r
	}

	action := actionTok
	currIdx := 1

	if kind == "standard" || strings.HasPrefix(kind, "standard") || kind == "named-std" {
		srcCubes, nextIdx := consumeIPSpec(toks, currIdx, groups, &unresolved)
		if srcCubes == nil {
			r := opaqueRule(ruleID, action, rawLine, "source address specification not understood")
			return &r
		}
		currIdx = nextIdx
		_ = currIdx
		if ruleID == "" {
			ruleID = "std"
		}
		return &Rule{
			ID:     ruleID,
			Action: action,
			Fields: FieldSet{
				SrcIPs: srcCubes,
				DstIPs: []Cube{CubeAny()},
			},
			RawText:    rawLine,
			Unresolved: unresolved,
		}
	}

	// Extended ACL
	if currIdx >= len(toks) {
		r := opaqueRule(ruleID, action, rawLine, "ACE ends before a protocol is given")
		return &r
	}

	protoTok := strings.ToLower(toks[currIdx])
	currIdx++
	protoNum := ProtoFromName(protoTok)
	if protoNum == nil && protoTok != "ip" && protoTok != "ipv4" && protoTok != "ip4" && protoTok != "any" && protoTok != "all" {
		r := opaqueRule(ruleID, action, rawLine, fmt.Sprintf("protocol token '%s' not understood", protoTok))
		return &r
	}
	var protos map[int]bool
	if protoNum != nil {
		protos = map[int]bool{*protoNum: true}
	}

	// Source IP spec
	srcCubes, nextIdx := consumeIPSpec(toks, currIdx, groups, &unresolved)
	if srcCubes == nil {
		r := opaqueRule(ruleID, action, rawLine, "source address specification not understood")
		return &r
	}
	currIdx = nextIdx

	// Source port spec (optional)
	srcPorts, nextIdx := consumePortSpec(toks, currIdx, groups, &unresolved)
	currIdx = nextIdx

	// Destination IP spec
	dstCubes, nextIdx := consumeIPSpec(toks, currIdx, groups, &unresolved)
	if dstCubes == nil {
		r := opaqueRule(ruleID, action, rawLine, "destination address specification not understood")
		return &r
	}
	currIdx = nextIdx

	// Destination port spec (optional)
	dstPorts, nextIdx := consumePortSpec(toks, currIdx, groups, &unresolved)
	currIdx = nextIdx

	// Trailing qualifiers
	established, icmpTypes, narrowing := consumeTrailingQualifiers(toks, currIdx, protoTok)
	if len(narrowing) > 0 {
		unresolved = append(unresolved, "ACE qualifier not evaluated: "+strings.Join(narrowing, ", "))
	}

	if ruleID == "" {
		ruleID = "ext"
	}
	return &Rule{
		ID:     ruleID,
		Action: action,
		Fields: FieldSet{
			SrcIPs:         srcCubes,
			DstIPs:         dstCubes,
			SrcPorts:       srcPorts,
			DstPorts:       dstPorts,
			Protos:         protos,
			Established:    established,
			ICMPTypes:      icmpTypes,
			NarrowingQuals: narrowing,
		},
		RawText:    rawLine,
		Unresolved: unresolved,
	}
}

// IOSPolicyEnvironment represents the full extracted policy and routing environment from an IOS running-config.
type IOSPolicyEnvironment struct {
	ACLs         map[string]*RuleSet
	Interfaces   map[string]map[string]any
	RouteTable   RouteTable
	ObjectGroups map[string]IOSObjectGroup
	Unresolved   []string
}

type iosBlock struct {
	bType  string
	header string
	body   []string
}

// ParseIOSConfig parses a Cisco IOS running-config into an IOSPolicyEnvironment.
func ParseIOSConfig(configText string) *IOSPolicyEnvironment {
	lines := strings.Split(configText, "\n")
	env := &IOSPolicyEnvironment{
		ACLs:         make(map[string]*RuleSet),
		Interfaces:   make(map[string]map[string]any),
		ObjectGroups: parseObjectGroups(lines),
	}

	var currentBlockType string
	var currentBlockHeader string
	var currentBlockLines []string
	var blocks []iosBlock

	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "!") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent == 0 {
			if currentBlockType != "" {
				blocks = append(blocks, iosBlock{
					bType:  currentBlockType,
					header: currentBlockHeader,
					body:   currentBlockLines,
				})
				currentBlockLines = nil
				currentBlockType = ""
			}

			low := strings.ToLower(s)
			if strings.HasPrefix(low, "interface ") {
				currentBlockType = "interface"
				currentBlockHeader = s
			} else if strings.HasPrefix(low, "ip access-list standard ") {
				currentBlockType = "named_std_acl"
				currentBlockHeader = s
			} else if strings.HasPrefix(low, "ip access-list extended ") {
				currentBlockType = "named_ext_acl"
				currentBlockHeader = s
			} else if strings.HasPrefix(low, "access-list ") {
				blocks = append(blocks, iosBlock{bType: "numbered_acl", header: s})
			} else if strings.HasPrefix(low, "ip route ") {
				blocks = append(blocks, iosBlock{bType: "static_route", header: s})
			} else if strings.HasPrefix(low, "router ") {
				currentBlockType = "router"
				currentBlockHeader = s
			}
		} else {
			if currentBlockType != "" {
				currentBlockLines = append(currentBlockLines, s)
			}
		}
	}
	if currentBlockType != "" {
		blocks = append(blocks, iosBlock{
			bType:  currentBlockType,
			header: currentBlockHeader,
			body:   currentBlockLines,
		})
	}

	var connectedRoutes []Route
	var staticRoutes []Route
	var dynamicProtocols []string

	for _, b := range blocks {
		switch b.bType {
		case "numbered_acl":
			if m := reNumberedACL.FindStringSubmatch(b.header); len(m) == 3 {
				num := m[1]
				n, _ := strconv.Atoi(num)
				kind := "extended"
				if (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999) {
					kind = "standard"
				}
				acl, ok := env.ACLs[num]
				if !ok {
					acl = &RuleSet{Name: num, Kind: fmt.Sprintf("numbered-%s", kind), DefaultAction: "deny"}
					env.ACLs[num] = acl
				}
				rule := ParseACELine(b.header, strconv.Itoa(len(acl.Rules)+1), kind, env.ObjectGroups)
				if rule != nil {
					acl.Rules = append(acl.Rules, *rule)
				}
			}
		case "named_std_acl", "named_ext_acl":
			kind := "named-ext"
			if b.bType == "named_std_acl" {
				kind = "named-std"
			}
			parts := strings.Fields(b.header)
			aclName := parts[len(parts)-1]
			acl, ok := env.ACLs[aclName]
			if !ok {
				acl = &RuleSet{Name: aclName, Kind: kind, DefaultAction: "deny"}
				env.ACLs[aclName] = acl
			}
			for _, bLine := range b.body {
				rule := ParseACELine(bLine, "", kind, env.ObjectGroups)
				if rule != nil {
					acl.Rules = append(acl.Rules, *rule)
				}
			}
		case "interface":
			intfName := strings.TrimSpace(b.header[10:])
			ifaceInfo := map[string]any{
				"name":          intfName,
				"ip":            "",
				"mask":          "",
				"prefix":        "",
				"secondary_ips": []map[string]string{},
				"acl_in":        nil,
				"acl_out":       nil,
				"shutdown":      false,
			}
			for _, bLine := range b.body {
				low := strings.ToLower(bLine)
				if low == "shutdown" {
					ifaceInfo["shutdown"] = true
				} else if strings.HasPrefix(low, "ip address ") {
					toks := strings.Fields(bLine)
					if len(toks) >= 4 && strings.ToLower(toks[1]) == "address" {
						ipVal, maskVal := toks[2], toks[3]
						pfxLen := 0
						if isIP(maskVal) {
							if mInt, err := IPToInt(maskVal); err == nil {
								if p := MaskToPrefixLen(mInt); p != nil {
									pfxLen = *p
								}
							}
						}
						cidr := fmt.Sprintf("%s/%d", ipVal, pfxLen)
						if strings.Contains(low, "secondary") {
							sec := ifaceInfo["secondary_ips"].([]map[string]string)
							ifaceInfo["secondary_ips"] = append(sec, map[string]string{
								"ip": ipVal, "mask": maskVal, "prefix": cidr,
							})
						} else {
							ifaceInfo["ip"] = ipVal
							ifaceInfo["mask"] = maskVal
							ifaceInfo["prefix"] = cidr
						}
					}
				} else if strings.HasPrefix(low, "ip access-group ") {
					toks := strings.Fields(bLine)
					if len(toks) >= 4 {
						grpName := toks[2]
						direction := strings.ToLower(toks[3])
						if direction == "in" {
							ifaceInfo["acl_in"] = grpName
						} else if direction == "out" {
							ifaceInfo["acl_out"] = grpName
						}
					}
				}
			}
			env.Interfaces[intfName] = ifaceInfo

			// Connected route
			isShut, _ := ifaceInfo["shutdown"].(bool)
			ipStr, _ := ifaceInfo["ip"].(string)
			maskStr, _ := ifaceInfo["mask"].(string)
			if !isShut && ipStr != "" && maskStr != "" {
				if pCube, err := CubeFromNetmask(ipStr, maskStr); err == nil {
					pfxLen := 24
					if p := MaskToPrefixLen(pCube.Mask); p != nil {
						pfxLen = *p
					}
					pfxStr := fmt.Sprintf("%s/%d", IntToIP(pCube.Value), pfxLen)
					connectedRoutes = append(connectedRoutes, Route{
						Prefix:     pfxStr,
						PrefixCube: pCube,
						Interface:  intfName,
						Source:     "connected",
						Distance:   0,
					})
				}
			}
		case "static_route":
			toks := strings.Fields(b.header)
			if len(toks) >= 3 {
				rest := toks[2:]
				if len(rest) >= 2 && strings.ToLower(rest[0]) == "vrf" {
					rest = rest[2:]
				}
				if len(rest) >= 3 {
					netStr, maskStr, nextHop := rest[0], rest[1], rest[2]
					if pCube, err := CubeFromNetmask(netStr, maskStr); err == nil {
						pfxLen := 0
						if p := MaskToPrefixLen(pCube.Mask); p != nil {
							pfxLen = *p
						}
						pfxStr := fmt.Sprintf("%s/%d", IntToIP(pCube.Value), pfxLen)
						var egressIf string
						var nextHopIP string
						if isIP(nextHop) {
							nextHopIP = nextHop
						} else {
							egressIf = nextHop
						}
						ad := 1
						if len(rest) > 3 {
							ad = staticRouteDistance(rest[3:])
						}
						staticRoutes = append(staticRoutes, Route{
							Prefix:     pfxStr,
							PrefixCube: pCube,
							NextHop:    nextHopIP,
							Interface:  egressIf,
							Source:     "static",
							Distance:   ad,
						})
					}
				}
			}
		case "router":
			toks := strings.Fields(b.header)
			protoName := "dynamic"
			if len(toks) > 1 {
				protoName = toks[1]
			}
			dynamicProtocols = append(dynamicProtocols, protoName)
		}
	}

	// Resolve static route egress interfaces
	var resolvedStatic []Route
	for _, sr := range staticRoutes {
		if sr.NextHop != "" && sr.Interface == "" {
			if nhInt, err := IPToInt(sr.NextHop); err == nil {
				var matchedConn *Route
				for i := range connectedRoutes {
					if connectedRoutes[i].PrefixCube.ContainsIP(nhInt) {
						matchedConn = &connectedRoutes[i]
						break
					}
				}
				if matchedConn != nil {
					resolvedStatic = append(resolvedStatic, Route{
						Prefix:     sr.Prefix,
						PrefixCube: sr.PrefixCube,
						NextHop:    sr.NextHop,
						Interface:  matchedConn.Interface,
						Source:     sr.Source,
						Distance:   sr.Distance,
					})
					continue
				}
			}
		}
		resolvedStatic = append(resolvedStatic, sr)
	}

	allRoutes := append(connectedRoutes, resolvedStatic...)
	env.RouteTable = RouteTable{
		Routes:                allRoutes,
		DynamicRoutingPresent: len(dynamicProtocols) > 0,
		Protocols:             dynamicProtocols,
	}

	return env
}
