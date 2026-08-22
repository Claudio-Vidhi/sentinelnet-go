package policytest

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

var (
	negateKeys = []string{
		"srcaddr-negate", "dstaddr-negate", "service-negate",
		"internet-service-negate", "internet-service-src-negate",
	}
	narrowingKeys = []string{
		"groups", "users", "fsso-groups", "application",
		"app-category", "app-group", "url-category",
	}
)

type fortiNode struct {
	sets     map[string][]string
	children []fortiChild
}

type fortiChild struct {
	name string
	node *fortiNode
}

func newFortiNode() *fortiNode {
	return &fortiNode{sets: make(map[string][]string)}
}

func (n *fortiNode) child(name string) *fortiNode {
	for _, c := range n.children {
		if c.name == name {
			return c.node
		}
	}
	ch := newFortiNode()
	n.children = append(n.children, fortiChild{name: name, node: ch})
	return ch
}

func (n *fortiNode) get(name string) *fortiNode {
	for _, c := range n.children {
		if c.name == name {
			return c.node
		}
	}
	return nil
}

func (n *fortiNode) set1(key, def string) string {
	if vals := n.sets[key]; len(vals) > 0 {
		return vals[0]
	}
	return def
}

func fortiTokens(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' {
			inQuote = !inQuote
			continue
		}
		if !inQuote && (ch == ' ' || ch == '\t') {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		} else {
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func fortiTree(text string) *fortiNode {
	root := newFortiNode()
	stack := []*fortiNode{root}

	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		toks := fortiTokens(s)
		if len(toks) == 0 {
			continue
		}

		verb := strings.ToLower(toks[0])
		switch verb {
		case "config":
			path := strings.Join(toks[1:], " ")
			cur := stack[len(stack)-1]
			ch := cur.child(path)
			stack = append(stack, ch)
		case "edit":
			name := strings.Join(toks[1:], " ")
			cur := stack[len(stack)-1]
			ch := cur.child(name)
			stack = append(stack, ch)
		case "set":
			if len(toks) >= 2 {
				key := strings.ToLower(toks[1])
				vals := toks[2:]
				cur := stack[len(stack)-1]
				cur.sets[key] = vals
			}
		case "next", "end":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return root
}

// ParsePortRanges parses a FortiOS portrange spec into destination port intervals.
func ParsePortRanges(spec string) []PortInterval {
	var intervals []PortInterval
	if spec == "" {
		return intervals
	}

	for _, chunk := range strings.Fields(spec) {
		dstHalf := strings.Split(chunk, ":")[0]
		for _, sub := range strings.Split(dstHalf, ",") {
			sub = strings.TrimSpace(sub)
			if sub == "" {
				continue
			}
			if strings.Contains(sub, "-") {
				parts := strings.SplitN(sub, "-", 2)
				p1, err1 := strconv.Atoi(parts[0])
				p2, err2 := strconv.Atoi(parts[1])
				if err1 == nil && err2 == nil {
					lo, hi := p1, p2
					if lo > hi {
						lo, hi = hi, lo
					}
					intervals = append(intervals, PortInterval{Lo: lo, Hi: hi})
				}
			} else if p, err := strconv.Atoi(sub); err == nil {
				intervals = append(intervals, PortInterval{Lo: p, Hi: p})
			}
		}
	}
	return intervals
}

func summarizeAddressRange(start, end uint32) []Cube {
	var cubes []Cube
	cur := start
	for cur <= end {
		// Find largest power of 2 aligned block
		maxSize := uint32(1)
		for (cur&(maxSize*2-1) == 0) && (cur+maxSize*2-1 <= end) && (maxSize < 0x80000000) {
			maxSize *= 2
		}
		pfx := 32 - bits.TrailingZeros32(maxSize)
		if c, err := CubeFromCIDR(IntToIP(cur), pfx); err == nil {
			cubes = append(cubes, c)
		}
		if maxSize == 0 || cur+maxSize < cur { // overflow check
			break
		}
		cur += maxSize
	}
	return cubes
}

func collectPolicyAddress(name string, pid string, env *FortiOSPolicyEnvironment, out *[]Cube, unresolved *[]string) {
	if builtin, ok := LookupBuiltinAddress(name); ok {
		*out = append(*out, builtin...)
		return
	}
	if cubes, ok := env.Addresses[name]; ok {
		if len(cubes) > 0 {
			*out = append(*out, cubes...)
		} else {
			*unresolved = append(*unresolved, fmt.Sprintf(
				"address '%s' referenced by policy %s cannot be resolved offline (FQDN, dynamic or geography object)",
				name, pid))
		}
		return
	}
	*unresolved = append(*unresolved, fmt.Sprintf("address '%s' referenced by policy %s is not defined", name, pid))
}

// FortiOSPolicyEnvironment represents the full extracted policy and routing environment from FortiOS config.
type FortiOSPolicyEnvironment struct {
	Policies   []Rule
	RouteTable RouteTable
	Interfaces map[string]map[string]any
	Addresses  map[string][]Cube
	Services   map[string]BuiltinServiceDef
	Unresolved []string
}

// ParseFortiOSConfig parses FortiOS config text into FortiOSPolicyEnvironment.
func ParseFortiOSConfig(configText string) *FortiOSPolicyEnvironment {
	root := fortiTree(configText)
	env := &FortiOSPolicyEnvironment{
		Interfaces: make(map[string]map[string]any),
		Addresses:  make(map[string][]Cube),
		Services:   make(map[string]BuiltinServiceDef),
	}

	// 1. Parse custom firewall addresses
	addrNode := root.get("firewall address")
	rawAddresses := make(map[string][]Cube)
	if addrNode != nil {
		for _, child := range addrNode.children {
			name := child.name
			entry := child.node
			atype := "ipmask"
			if t := entry.set1("type", ""); t != "" {
				atype = strings.ToLower(t)
			}

			if atype == "ipmask" {
				subnet := entry.sets["subnet"]
				if len(subnet) >= 2 && isIP(subnet[0]) && isIP(subnet[1]) {
					if cube, err := CubeFromNetmask(subnet[0], subnet[1]); err == nil {
						rawAddresses[name] = []Cube{cube}
					}
				} else if len(subnet) == 1 && strings.Contains(subnet[0], "/") {
					parts := strings.SplitN(subnet[0], "/", 2)
					if isIP(parts[0]) {
						if pfx, err := strconv.Atoi(parts[1]); err == nil {
							if cube, err := CubeFromCIDR(parts[0], pfx); err == nil {
								rawAddresses[name] = []Cube{cube}
							}
						}
					}
				}
			} else if atype == "iprange" {
				startIP := entry.set1("start-ip", "")
				endIP := entry.set1("end-ip", "")
				if isIP(startIP) && isIP(endIP) {
					sInt, err1 := IPToInt(startIP)
					eInt, err2 := IPToInt(endIP)
					if err1 == nil && err2 == nil {
						if sInt == eInt {
							if cube, err := CubeFromIP(startIP); err == nil {
								rawAddresses[name] = []Cube{cube}
							}
						} else {
							rawAddresses[name] = summarizeAddressRange(sInt, eInt)
						}
					}
				}
			} else if atype == "fqdn" {
				rawAddresses[name] = []Cube{}
			}
		}
	}

	// 2. Parse firewall addrgrp
	addrgrpNode := root.get("firewall addrgrp")
	addrGroupsRaw := make(map[string][]string)
	if addrgrpNode != nil {
		for _, child := range addrgrpNode.children {
			addrGroupsRaw[child.name] = append([]string{}, child.node.sets["member"]...)
		}
	}

	resolvedAddresses := make(map[string][]Cube)
	for k, v := range rawAddresses {
		resolvedAddresses[k] = v
	}
	for gname, members := range addrGroupsRaw {
		var allCubes []Cube
		seen := map[string]bool{gname: true}
		queue := append([]string{}, members...)

		for len(queue) > 0 {
			m := queue[0]
			queue = queue[1:]
			if seen[m] {
				continue
			}
			seen[m] = true
			if bCubes, ok := LookupBuiltinAddress(m); ok {
				allCubes = append(allCubes, bCubes...)
			} else if c, ok := rawAddresses[m]; ok {
				allCubes = append(allCubes, c...)
			} else if subs, ok := addrGroupsRaw[m]; ok {
				queue = append(queue, subs...)
			}
		}
		resolvedAddresses[gname] = allCubes
	}
	env.Addresses = resolvedAddresses

	// 3. Parse custom services
	svcNode := root.get("firewall service custom")
	rawServices := make(map[string]BuiltinServiceDef)
	if svcNode != nil {
		for _, child := range svcNode.children {
			name := child.name
			entry := child.node
			protocol := strings.ToUpper(entry.set1("protocol", "TCP/UDP/SCTP"))
			tcpRange := entry.set1("tcp-portrange", "")
			udpRange := entry.set1("udp-portrange", "")
			protoNumStr := entry.set1("protocol-number", "")

			if protocol == "IP" && protoNumStr != "" {
				if pNum, err := strconv.Atoi(protoNumStr); err == nil {
					rawServices[name] = BuiltinServiceDef{
						Protos: map[int]bool{pNum: true},
					}
				}
			} else if protocol == "ICMP" {
				icmptype := entry.set1("icmptype", "")
				var svcICMP map[int]bool
				if icmptype != "" {
					if n, err := strconv.Atoi(icmptype); err == nil {
						svcICMP = map[int]bool{n: true}
					}
				}
				rawServices[name] = BuiltinServiceDef{
					Protos:    map[int]bool{1: true},
					ICMPTypes: svcICMP,
				}
			} else {
				protos := make(map[int]bool)
				var ports []PortInterval
				if tcpRange != "" {
					protos[6] = true
					ports = append(ports, ParsePortRanges(tcpRange)...)
				}
				if udpRange != "" {
					protos[17] = true
					ports = append(ports, ParsePortRanges(udpRange)...)
				}
				if len(protos) == 0 {
					protos[6] = true
					protos[17] = true
				}
				var dstPorts *PortSet
				if len(ports) > 0 {
					ps := NewPortSet(ports)
					dstPorts = &ps
				}
				rawServices[name] = BuiltinServiceDef{
					Protos:   protos,
					DstPorts: dstPorts,
				}
			}
		}
	}

	// 4. Parse service groups
	svcgrpNode := root.get("firewall service group")
	svcGroupsRaw := make(map[string][]string)
	if svcgrpNode != nil {
		for _, child := range svcgrpNode.children {
			svcGroupsRaw[child.name] = append([]string{}, child.node.sets["member"]...)
		}
	}

	resolvedServices := make(map[string]BuiltinServiceDef)
	for k, v := range rawServices {
		resolvedServices[k] = v
	}
	for gname, members := range svcGroupsRaw {
		allProtos := make(map[int]bool)
		var allPorts []PortInterval
		allICMP := make(map[int]bool)
		anyProto := false
		anyPorts := false
		anyICMP := false

		seen := map[string]bool{gname: true}
		queue := append([]string{}, members...)

		for len(queue) > 0 {
			m := queue[0]
			queue = queue[1:]
			if seen[m] {
				continue
			}
			seen[m] = true

			var svcDef *BuiltinServiceDef
			if bSvc, ok := LookupBuiltinService(m); ok {
				svcDef = bSvc
			} else if sDef, ok := rawServices[m]; ok {
				svcDef = &sDef
			}

			if svcDef != nil {
				if svcDef.Protos == nil {
					anyProto = true
				} else {
					for p := range svcDef.Protos {
						allProtos[p] = true
					}
				}
				if svcDef.DstPorts == nil {
					anyPorts = true
				} else {
					allPorts = append(allPorts, svcDef.DstPorts.Intervals...)
				}
				if svcDef.ICMPTypes == nil {
					anyICMP = true
				} else {
					for t := range svcDef.ICMPTypes {
						allICMP[t] = true
					}
				}
			} else if subs, ok := svcGroupsRaw[m]; ok {
				queue = append(queue, subs...)
			}
		}

		var finalProtos map[int]bool
		if !anyProto && len(allProtos) > 0 {
			finalProtos = allProtos
		}
		var finalPorts *PortSet
		if !anyPorts && len(allPorts) > 0 {
			ps := NewPortSet(allPorts)
			finalPorts = &ps
		}
		var finalICMP map[int]bool
		if !anyICMP && len(allICMP) > 0 {
			finalICMP = allICMP
		}

		resolvedServices[gname] = BuiltinServiceDef{
			Protos:    finalProtos,
			DstPorts:  finalPorts,
			ICMPTypes: finalICMP,
		}
	}
	env.Services = resolvedServices

	// 5. Parse system interface
	intfNode := root.get("system interface")
	var connectedRoutes []Route
	if intfNode != nil {
		for _, child := range intfNode.children {
			name := child.name
			entry := child.node
			ipToks := entry.sets["ip"]
			status := strings.ToLower(entry.set1("status", "up"))
			if len(ipToks) >= 2 && isIP(ipToks[0]) && isIP(ipToks[1]) {
				ipStr, maskStr := ipToks[0], ipToks[1]
				env.Interfaces[name] = map[string]any{
					"name":   name,
					"ip":     ipStr,
					"mask":   maskStr,
					"status": status,
				}
				if status == "up" && ipStr != "0.0.0.0" {
					if pCube, err := CubeFromNetmask(ipStr, maskStr); err == nil {
						pfxLen := 24
						if p := MaskToPrefixLen(pCube.Mask); p != nil {
							pfxLen = *p
						}
						pfxStr := fmt.Sprintf("%s/%d", IntToIP(pCube.Value), pfxLen)
						connectedRoutes = append(connectedRoutes, Route{
							Prefix:     pfxStr,
							PrefixCube: pCube,
							Interface:  name,
							Source:     "connected",
							Distance:   0,
						})
					}
				}
			}
		}
	}

	// 6. Parse static routes
	staticNode := root.get("router static")
	var staticRoutes []Route
	if staticNode != nil {
		for _, child := range staticNode.children {
			entry := child.node
			status := strings.ToLower(entry.set1("status", "enable"))
			if status == "disable" {
				continue
			}
			dst := entry.sets["dst"]
			if len(dst) == 0 {
				dst = []string{"0.0.0.0", "0.0.0.0"}
			}
			gw := entry.set1("gateway", "")
			device := entry.set1("device", "")
			distStr := entry.set1("distance", "10")
			distance, err := strconv.Atoi(distStr)
			if err != nil {
				distance = 10
			}

			if len(dst) >= 2 && isIP(dst[0]) && isIP(dst[1]) {
				netStr, maskStr := dst[0], dst[1]
				if pCube, err := CubeFromNetmask(netStr, maskStr); err == nil {
					pfxLen := 0
					if p := MaskToPrefixLen(pCube.Mask); p != nil {
						pfxLen = *p
					}
					pfxStr := fmt.Sprintf("%s/%d", IntToIP(pCube.Value), pfxLen)
					egressIntf := device
					if gw != "" && egressIntf == "" {
						if gwInt, err := IPToInt(gw); err == nil {
							for _, cr := range connectedRoutes {
								if cr.PrefixCube.ContainsIP(gwInt) {
									egressIntf = cr.Interface
									break
								}
							}
						}
					}
					staticRoutes = append(staticRoutes, Route{
						Prefix:     pfxStr,
						PrefixCube: pCube,
						NextHop:    gw,
						Interface:  egressIntf,
						Source:     "static",
						Distance:   distance,
					})
				}
			}
		}
	}

	dynamicPresent := root.get("router ospf") != nil || root.get("router bgp") != nil
	var dynamicProtos []string
	if root.get("router ospf") != nil {
		dynamicProtos = append(dynamicProtos, "ospf")
	}
	if root.get("router bgp") != nil {
		dynamicProtos = append(dynamicProtos, "bgp")
	}

	env.RouteTable = RouteTable{
		Routes:                append(connectedRoutes, staticRoutes...),
		DynamicRoutingPresent: dynamicPresent,
		Protocols:             dynamicProtos,
	}

	// 7. Parse firewall policy
	polNode := root.get("firewall policy")
	if polNode != nil {
		for _, child := range polNode.children {
			pid := child.name
			entry := child.node
			name := entry.set1("name", "")
			actionRaw := strings.ToLower(entry.set1("action", "deny"))
			action := "deny"
			if actionRaw == "accept" {
				action = "permit"
			}
			status := strings.ToLower(entry.set1("status", "enable"))
			disabled := status == "disable"
			natRaw := strings.ToLower(entry.set1("nat", "disable"))
			natEnabled := natRaw == "enable"

			srcintfList := entry.sets["srcintf"]
			if len(srcintfList) == 0 {
				srcintfList = []string{"any"}
			}
			dstintfList := entry.sets["dstintf"]
			if len(dstintfList) == 0 {
				dstintfList = []string{"any"}
			}
			srcaddrList := entry.sets["srcaddr"]
			if len(srcaddrList) == 0 {
				srcaddrList = []string{"all"}
			}
			dstaddrList := entry.sets["dstaddr"]
			if len(dstaddrList) == 0 {
				dstaddrList = []string{"all"}
			}
			serviceList := entry.sets["service"]
			if len(serviceList) == 0 {
				serviceList = []string{"ALL"}
			}

			var policyUnresolved []string
			if actionRaw == "ipsec" {
				policyUnresolved = append(policyUnresolved, fmt.Sprintf(
					"policy %s uses the legacy 'ipsec' action: the traffic is forwarded into a VPN tunnel, which is neither a plain accept nor a deny",
					pid))
			}

			var ingressIntfs map[string]bool
			hasAnySrcIntf := false
			for _, i := range srcintfList {
				if strings.ToLower(i) == "any" {
					hasAnySrcIntf = true
					break
				}
			}
			if !hasAnySrcIntf {
				ingressIntfs = make(map[string]bool)
				for _, i := range srcintfList {
					ingressIntfs[i] = true
				}
			}

			var egressIntfs map[string]bool
			hasAnyDstIntf := false
			for _, i := range dstintfList {
				if strings.ToLower(i) == "any" {
					hasAnyDstIntf = true
					break
				}
			}
			if !hasAnyDstIntf {
				egressIntfs = make(map[string]bool)
				for _, i := range dstintfList {
					egressIntfs[i] = true
				}
			}

			var srcCubes []Cube
			for _, a := range srcaddrList {
				collectPolicyAddress(a, pid, env, &srcCubes, &policyUnresolved)
			}

			var dstCubes []Cube
			for _, a := range dstaddrList {
				collectPolicyAddress(a, pid, env, &dstCubes, &policyUnresolved)
			}

			var polProtos map[int]bool
			var polPorts []PortInterval
			var polICMP map[int]bool
			hasService := false
			serviceProtos := make(map[int]bool)
			var servicePorts []PortInterval
			serviceICMP := make(map[int]bool)
			anyProto := false
			anyPort := false
			anyICMPType := false

			for _, s := range serviceList {
				var sDef *BuiltinServiceDef
				if bSvc, ok := LookupBuiltinService(s); ok {
					sDef = bSvc
				} else if def, ok := env.Services[s]; ok {
					sDef = &def
				}

				if sDef != nil {
					hasService = true
					if sDef.Protos == nil {
						anyProto = true
					} else {
						for p := range sDef.Protos {
							serviceProtos[p] = true
						}
					}
					if sDef.DstPorts == nil {
						anyPort = true
					} else {
						servicePorts = append(servicePorts, sDef.DstPorts.Intervals...)
					}
					if sDef.ICMPTypes == nil {
						anyICMPType = true
					} else {
						for t := range sDef.ICMPTypes {
							serviceICMP[t] = true
						}
					}
				} else {
					policyUnresolved = append(policyUnresolved, fmt.Sprintf("service '%s' referenced by policy %s is not defined", s, pid))
				}
			}

			if hasService {
				if !anyProto && len(serviceProtos) > 0 {
					polProtos = serviceProtos
				}
				if !anyPort && len(servicePorts) > 0 {
					polPorts = servicePorts
				}
				if !anyICMPType && len(serviceICMP) > 0 {
					polICMP = serviceICMP
				}
			}

			if entry.set1("internet-service", "") == "enable" || len(entry.sets["internet-service-name"]) > 0 ||
				entry.set1("internet-service-src", "") == "enable" || len(entry.sets["internet-service-src-name"]) > 0 {
				policyUnresolved = append(policyUnresolved, fmt.Sprintf("policy %s references ISDB internet-service which cannot be resolved offline", pid))
			}

			for _, negKey := range negateKeys {
				if entry.set1(negKey, "") == "enable" {
					policyUnresolved = append(policyUnresolved, fmt.Sprintf("policy %s sets %s: the match is inverted and cannot be modelled", pid, negKey))
				}
			}

			var policyNarrowing []string
			sched := entry.set1("schedule", "always")
			if sched != "" && sched != "always" {
				policyNarrowing = append(policyNarrowing, "schedule "+sched)
			}
			for _, narrowKey := range narrowingKeys {
				if len(entry.sets[narrowKey]) > 0 {
					policyNarrowing = append(policyNarrowing, narrowKey)
				}
			}
			if len(policyNarrowing) > 0 {
				policyUnresolved = append(policyUnresolved, fmt.Sprintf("policy %s condition not evaluated: %s", pid, strings.Join(policyNarrowing, ", ")))
			}

			finalSrcCubes := srcCubes
			if len(finalSrcCubes) == 0 {
				finalSrcCubes = []Cube{CubeAny()}
			}
			finalDstCubes := dstCubes
			if len(finalDstCubes) == 0 {
				finalDstCubes = []Cube{CubeAny()}
			}
			var finalDstPorts *PortSet
			if polPorts != nil {
				ps := NewPortSet(polPorts)
				finalDstPorts = &ps
			}

			fieldSet := FieldSet{
				SrcIPs:         finalSrcCubes,
				DstIPs:         finalDstCubes,
				SrcPorts:       nil,
				DstPorts:       finalDstPorts,
				Protos:         polProtos,
				ICMPTypes:      polICMP,
				IngressIntfs:   ingressIntfs,
				EgressIntfs:    egressIntfs,
				Opaque:         len(policyUnresolved) > 0,
				NarrowingQuals: policyNarrowing,
			}

			var rawBuilder strings.Builder
			rawBuilder.WriteString(fmt.Sprintf("edit %s\n", pid))
			for k, v := range entry.sets {
				rawBuilder.WriteString(fmt.Sprintf("  set %s %s\n", k, strings.Join(v, " ")))
			}

			ruleAction := action
			if len(policyUnresolved) > 0 {
				ruleAction = "unknown"
			}

			rule := Rule{
				ID:         pid,
				Name:       name,
				Action:     ruleAction,
				Fields:     fieldSet,
				Disabled:   disabled,
				RawText:    strings.TrimRight(rawBuilder.String(), "\n"),
				NATEnabled: natEnabled,
				Unresolved: policyUnresolved,
			}
			env.Policies = append(env.Policies, rule)
			if len(policyUnresolved) > 0 {
				env.Unresolved = append(env.Unresolved, policyUnresolved...)
			}
		}
	}

	return env
}
