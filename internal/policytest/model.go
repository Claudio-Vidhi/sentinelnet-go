// Package policytest: Data models, parser and evaluation engine for Policy & Route Validation.
// Pure model with zero I/O.
// Port of services/policy_test/model.py.
package policytest

import (
	"fmt"
	"math/bits"
	"net"
	"sort"
	"strings"
)

// IPToInt converts an IPv4 address string to a 32-bit unsigned integer.
func IPToInt(ipStr string) (uint32, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

// IntToIP converts a 32-bit unsigned integer to an IPv4 address string.
func IntToIP(val uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
}

// MaskToPrefixLen returns prefix length if mask is contiguous from MSB, else nil.
func MaskToPrefixLen(mask uint32) *int {
	if mask == 0 {
		zero := 0
		return &zero
	}
	inv := ^mask
	if ((inv + 1) & inv) == 0 {
		ones := bits.OnesCount32(mask)
		var expected uint32
		if ones > 0 {
			expected = uint32(0xFFFFFFFF) << (32 - ones)
		}
		if mask == expected {
			res := ones
			return &res
		}
	}
	return nil
}

// Cube represents a ternary cube representing an IPv4 subnet or wildcard pattern.
type Cube struct {
	Value uint32 `json:"value"`
	Mask  uint32 `json:"mask"`
}

// NewCube creates a normalized Cube.
func NewCube(value, mask uint32) Cube {
	return Cube{
		Value: value & mask,
		Mask:  mask,
	}
}

func (c Cube) ContainsIP(ip uint32) bool {
	return ((ip & c.Mask) ^ c.Value) == 0
}

func (c Cube) ContainsCube(other Cube) bool {
	if (c.Mask & other.Mask) != c.Mask {
		return false
	}
	return ((c.Value ^ other.Value) & c.Mask) == 0
}

func (c Cube) Intersects(other Cube) bool {
	commonMask := c.Mask & other.Mask
	return ((c.Value ^ other.Value) & commonMask) == 0
}

func (c Cube) IsAny() bool {
	return c.Mask == 0
}

func (c Cube) IsExact() bool {
	return c.Mask == 0xFFFFFFFF
}

func (c Cube) ToStr() string {
	if c.IsAny() {
		return "any"
	}
	if c.IsExact() {
		return fmt.Sprintf("host %s", IntToIP(c.Value))
	}
	prefix := MaskToPrefixLen(c.Mask)
	if prefix != nil {
		return fmt.Sprintf("%s/%d", IntToIP(c.Value), *prefix)
	}
	wildcardInt := ^c.Mask
	return fmt.Sprintf("%s %s", IntToIP(c.Value), IntToIP(wildcardInt))
}

func CubeFromIP(ip string) (Cube, error) {
	val, err := IPToInt(ip)
	if err != nil {
		return Cube{}, err
	}
	return NewCube(val, 0xFFFFFFFF), nil
}

func CubeFromCIDR(ip string, prefix int) (Cube, error) {
	if prefix < 0 || prefix > 32 {
		return Cube{}, fmt.Errorf("invalid prefix length: %d", prefix)
	}
	val, err := IPToInt(ip)
	if err != nil {
		return Cube{}, err
	}
	var mask uint32
	if prefix > 0 {
		mask = uint32(0xFFFFFFFF) << (32 - prefix)
	}
	return NewCube(val, mask), nil
}

func CubeFromNetmask(ip, netmask string) (Cube, error) {
	val, err := IPToInt(ip)
	if err != nil {
		return Cube{}, err
	}
	mask, err := IPToInt(netmask)
	if err != nil {
		return Cube{}, err
	}
	return NewCube(val, mask), nil
}

func CubeFromWildcard(ip, wildcard string) (Cube, error) {
	val, err := IPToInt(ip)
	if err != nil {
		return Cube{}, err
	}
	wildcardInt, err := IPToInt(wildcard)
	if err != nil {
		return Cube{}, err
	}
	mask := ^wildcardInt
	return NewCube(val, mask), nil
}

func CubeAny() Cube {
	return Cube{Value: 0, Mask: 0}
}

// PortInterval represents a closed port interval [Lo, Hi].
type PortInterval struct {
	Lo int `json:"lo"`
	Hi int `json:"hi"`
}

// PortSet represents a collection of closed port intervals [(lo, hi), ...].
type PortSet struct {
	Intervals []PortInterval `json:"intervals"`
}

func normalizeIntervals(intervals []PortInterval) []PortInterval {
	var cleaned []PortInterval
	for _, iv := range intervals {
		lo := iv.Lo
		hi := iv.Hi
		if lo < 0 {
			lo = 0
		}
		if lo > 65535 {
			lo = 65535
		}
		if hi < 0 {
			hi = 0
		}
		if hi > 65535 {
			hi = 65535
		}
		if lo > hi {
			lo, hi = hi, lo
		}
		cleaned = append(cleaned, PortInterval{Lo: lo, Hi: hi})
	}
	if len(cleaned) == 0 {
		return nil
	}
	sort.Slice(cleaned, func(i, j int) bool {
		if cleaned[i].Lo == cleaned[j].Lo {
			return cleaned[i].Hi < cleaned[j].Hi
		}
		return cleaned[i].Lo < cleaned[j].Lo
	})
	merged := []PortInterval{cleaned[0]}
	for _, cur := range cleaned[1:] {
		prev := &merged[len(merged)-1]
		if cur.Lo <= prev.Hi+1 {
			if cur.Hi > prev.Hi {
				prev.Hi = cur.Hi
			}
		} else {
			merged = append(merged, cur)
		}
	}
	return merged
}

func NewPortSet(intervals []PortInterval) PortSet {
	return PortSet{Intervals: normalizeIntervals(intervals)}
}

func (ps PortSet) ContainsPort(port int) bool {
	for _, iv := range ps.Intervals {
		if iv.Lo <= port && port <= iv.Hi {
			return true
		}
	}
	return false
}

func (ps PortSet) ContainsPortSet(other PortSet) bool {
	for _, oiv := range other.Intervals {
		covered := false
		for _, siv := range ps.Intervals {
			if siv.Lo <= oiv.Lo && oiv.Hi <= siv.Hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func (ps PortSet) Intersects(other PortSet) bool {
	for _, siv := range ps.Intervals {
		for _, oiv := range other.Intervals {
			maxLo := siv.Lo
			if oiv.Lo > maxLo {
				maxLo = oiv.Lo
			}
			minHi := siv.Hi
			if oiv.Hi < minHi {
				minHi = oiv.Hi
			}
			if maxLo <= minHi {
				return true
			}
		}
	}
	return false
}

func (ps PortSet) IsAny() bool {
	return len(ps.Intervals) == 1 && ps.Intervals[0].Lo <= 1 && ps.Intervals[0].Hi == 65535
}

func PortSetFromOp(op string, val1 int, val2 ...int) PortSet {
	op = strings.ToLower(strings.TrimSpace(op))
	switch op {
	case "eq":
		return NewPortSet([]PortInterval{{Lo: val1, Hi: val1}})
	case "gt":
		return NewPortSet([]PortInterval{{Lo: val1 + 1, Hi: 65535}})
	case "lt":
		lo := 1
		hi := val1 - 1
		if hi < 1 {
			hi = 1
		}
		return NewPortSet([]PortInterval{{Lo: lo, Hi: hi}})
	case "range":
		v2 := val1
		if len(val2) > 0 {
			v2 = val2[0]
		}
		lo := val1
		hi := v2
		if lo > hi {
			lo, hi = hi, lo
		}
		return NewPortSet([]PortInterval{{Lo: lo, Hi: hi}})
	case "neq":
		var res []PortInterval
		if val1 > 1 {
			res = append(res, PortInterval{Lo: 1, Hi: val1 - 1})
		}
		if val1 < 65535 {
			res = append(res, PortInterval{Lo: val1 + 1, Hi: 65535})
		}
		return NewPortSet(res)
	default:
		return PortSetAny()
	}
}

func PortSetAny() PortSet {
	return PortSet{Intervals: []PortInterval{{Lo: 0, Hi: 65535}}}
}

// Flow represents a packet flow to trace through the policy and route chain.
type Flow struct {
	SrcIP        string  `json:"src_ip"`
	DstIP        string  `json:"dst_ip"`
	Proto        string  `json:"proto"`
	SPort        *int    `json:"sport,omitempty"`
	DPort        *int    `json:"dport,omitempty"`
	IngressIntf  string  `json:"ingress_intf,omitempty"`
	EgressIntf   string  `json:"egress_intf,omitempty"`
	TCPFlags     string  `json:"tcp_flags,omitempty"`
	Established  bool    `json:"established"`
	ICMPType     *int    `json:"icmp_type,omitempty"`
}

func (f Flow) ToMap() map[string]any {
	m := map[string]any{
		"src_ip":      f.SrcIP,
		"dst_ip":      f.DstIP,
		"proto":       f.Proto,
		"established": f.Established,
	}
	if f.SPort != nil {
		m["sport"] = *f.SPort
	}
	if f.DPort != nil {
		m["dport"] = *f.DPort
	}
	if f.IngressIntf != "" {
		m["ingress_intf"] = f.IngressIntf
	}
	if f.EgressIntf != "" {
		m["egress_intf"] = f.EgressIntf
	}
	if f.TCPFlags != "" {
		m["tcp_flags"] = f.TCPFlags
	}
	if f.ICMPType != nil {
		m["icmp_type"] = *f.ICMPType
	}
	return m
}

// FieldSet represents a multidimensional packet domain for an ACE or firewall rule.
type FieldSet struct {
	SrcIPs         []Cube          `json:"src_ips"`
	DstIPs         []Cube          `json:"dst_ips"`
	SrcPorts       *PortSet        `json:"src_ports,omitempty"`
	DstPorts       *PortSet        `json:"dst_ports,omitempty"`
	Protos         map[int]bool    `json:"protos,omitempty"`
	IngressIntfs   map[string]bool `json:"ingress_intfs,omitempty"`
	EgressIntfs    map[string]bool `json:"egress_intfs,omitempty"`
	Established    bool            `json:"established"`
	Opaque         bool            `json:"opaque"`
	ICMPTypes      map[int]bool    `json:"icmp_types,omitempty"`
	NarrowingQuals []string        `json:"narrowing_quals,omitempty"`
}

func NewFieldSet() FieldSet {
	return FieldSet{
		SrcIPs: []Cube{CubeAny()},
		DstIPs: []Cube{CubeAny()},
	}
}

func (fs FieldSet) IsAnyAny() bool {
	if fs.Opaque {
		return false
	}
	srcAny := true
	for _, c := range fs.SrcIPs {
		if !c.IsAny() {
			srcAny = false
			break
		}
	}
	dstAny := true
	for _, c := range fs.DstIPs {
		if !c.IsAny() {
			dstAny = false
			break
		}
	}
	sportAny := fs.SrcPorts == nil || fs.SrcPorts.IsAny()
	dportAny := fs.DstPorts == nil || fs.DstPorts.IsAny()
	protoAny := len(fs.Protos) == 0 && len(fs.ICMPTypes) == 0
	intfAny := len(fs.IngressIntfs) == 0 && len(fs.EgressIntfs) == 0
	return srcAny && dstAny && sportAny && dportAny && protoAny && intfAny && !fs.Established && len(fs.NarrowingQuals) == 0
}

func (fs FieldSet) Contains(other FieldSet) bool {
	if fs.Opaque || other.Opaque {
		return false
	}
	if len(fs.NarrowingQuals) > 0 {
		return false
	}
	if fs.Established && !other.Established {
		return false
	}
	// Protocols: if fs specifies protocols, other must also specify and be a subset
	if len(fs.Protos) > 0 {
		if len(other.Protos) == 0 {
			return false
		}
		for p := range other.Protos {
			if !fs.Protos[p] {
				return false
			}
		}
	}
	// ICMP types
	if len(fs.ICMPTypes) > 0 {
		if len(other.ICMPTypes) == 0 {
			return false
		}
		for t := range other.ICMPTypes {
			if !fs.ICMPTypes[t] {
				return false
			}
		}
	}
	// Src IPs: every cube in other must be covered by at least one cube in fs
	for _, oc := range other.SrcIPs {
		covered := false
		for _, sc := range fs.SrcIPs {
			if sc.ContainsCube(oc) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	// Dst IPs
	for _, oc := range other.DstIPs {
		covered := false
		for _, sc := range fs.DstIPs {
			if sc.ContainsCube(oc) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	// Src ports
	if fs.SrcPorts != nil {
		if other.SrcPorts == nil {
			return false
		}
		if !fs.SrcPorts.ContainsPortSet(*other.SrcPorts) {
			return false
		}
	}
	// Dst ports
	if fs.DstPorts != nil {
		if other.DstPorts == nil {
			return false
		}
		if !fs.DstPorts.ContainsPortSet(*other.DstPorts) {
			return false
		}
	}
	// Ingress interfaces
	if len(fs.IngressIntfs) > 0 {
		if len(other.IngressIntfs) == 0 {
			return false
		}
		sLow := make(map[string]bool)
		for i := range fs.IngressIntfs {
			sLow[strings.ToLower(i)] = true
		}
		for i := range other.IngressIntfs {
			if !sLow[strings.ToLower(i)] {
				return false
			}
		}
	}
	// Egress interfaces
	if len(fs.EgressIntfs) > 0 {
		if len(other.EgressIntfs) == 0 {
			return false
		}
		sLow := make(map[string]bool)
		for i := range fs.EgressIntfs {
			sLow[strings.ToLower(i)] = true
		}
		for i := range other.EgressIntfs {
			if !sLow[strings.ToLower(i)] {
				return false
			}
		}
	}
	return true
}

func (fs FieldSet) Intersects(other FieldSet) bool {
	if fs.Opaque || other.Opaque {
		return false
	}
	// Protocols
	if len(fs.Protos) > 0 && len(other.Protos) > 0 {
		common := false
		for p := range fs.Protos {
			if other.Protos[p] {
				common = true
				break
			}
		}
		if !common {
			return false
		}
	}
	// ICMP types
	if len(fs.ICMPTypes) > 0 && len(other.ICMPTypes) > 0 {
		common := false
		for t := range fs.ICMPTypes {
			if other.ICMPTypes[t] {
				common = true
				break
			}
		}
		if !common {
			return false
		}
	}
	// Src IPs
	srcMatch := false
	for _, sc := range fs.SrcIPs {
		for _, oc := range other.SrcIPs {
			if sc.Intersects(oc) {
				srcMatch = true
				break
			}
		}
		if srcMatch {
			break
		}
	}
	if !srcMatch {
		return false
	}
	// Dst IPs
	dstMatch := false
	for _, sc := range fs.DstIPs {
		for _, oc := range other.DstIPs {
			if sc.Intersects(oc) {
				dstMatch = true
				break
			}
		}
		if dstMatch {
			break
		}
	}
	if !dstMatch {
		return false
	}
	// Src Ports
	if fs.SrcPorts != nil && other.SrcPorts != nil {
		if !fs.SrcPorts.Intersects(*other.SrcPorts) {
			return false
		}
	}
	// Dst Ports
	if fs.DstPorts != nil && other.DstPorts != nil {
		if !fs.DstPorts.Intersects(*other.DstPorts) {
			return false
		}
	}
	// Ingress interfaces
	if len(fs.IngressIntfs) > 0 && len(other.IngressIntfs) > 0 {
		sLow := make(map[string]bool)
		for i := range fs.IngressIntfs {
			sLow[strings.ToLower(i)] = true
		}
		common := false
		for i := range other.IngressIntfs {
			if sLow[strings.ToLower(i)] {
				common = true
				break
			}
		}
		if !common {
			return false
		}
	}
	// Egress interfaces
	if len(fs.EgressIntfs) > 0 && len(other.EgressIntfs) > 0 {
		sLow := make(map[string]bool)
		for i := range fs.EgressIntfs {
			sLow[strings.ToLower(i)] = true
		}
		common := false
		for i := range other.EgressIntfs {
			if sLow[strings.ToLower(i)] {
				common = true
				break
			}
		}
		if !common {
			return false
		}
	}
	return true
}

func (fs FieldSet) Matches(flow Flow) bool {
	if fs.Opaque {
		return false
	}
	return fs.matchKnownDimensions(flow)
}

func (fs FieldSet) MayMatch(flow Flow) bool {
	return fs.matchKnownDimensions(flow)
}

func (fs FieldSet) matchKnownDimensions(flow Flow) bool {
	if fs.Established {
		if !flow.Established && !strings.Contains(strings.ToLower(flow.TCPFlags), "established") {
			return false
		}
	}
	// Protocol
	flowPNum := ProtoFromName(flow.Proto)
	if len(fs.Protos) > 0 {
		if flowPNum != nil && !fs.Protos[*flowPNum] {
			return false
		}
	}
	// ICMP type
	if len(fs.ICMPTypes) > 0 && flow.ICMPType != nil {
		if !fs.ICMPTypes[*flow.ICMPType] {
			return false
		}
	}
	// Src IP
	sIP, err := IPToInt(flow.SrcIP)
	if err == nil {
		matched := false
		for _, c := range fs.SrcIPs {
			if c.ContainsIP(sIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	} else {
		return false
	}
	// Dst IP
	dIP, err := IPToInt(flow.DstIP)
	if err == nil {
		matched := false
		for _, c := range fs.DstIPs {
			if c.ContainsIP(dIP) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	} else {
		return false
	}
	// Src port
	if fs.SrcPorts != nil && flow.SPort != nil {
		if !fs.SrcPorts.ContainsPort(*flow.SPort) {
			return false
		}
	}
	// Dst port
	if fs.DstPorts != nil && flow.DPort != nil {
		if !fs.DstPorts.ContainsPort(*flow.DPort) {
			return false
		}
	}
	// Ingress interface
	if len(fs.IngressIntfs) > 0 && flow.IngressIntf != "" {
		sLow := make(map[string]bool)
		for i := range fs.IngressIntfs {
			sLow[strings.ToLower(i)] = true
		}
		if !sLow[strings.ToLower(flow.IngressIntf)] {
			return false
		}
	}
	// Egress interface
	if len(fs.EgressIntfs) > 0 && flow.EgressIntf != "" {
		sLow := make(map[string]bool)
		for i := range fs.EgressIntfs {
			sLow[strings.ToLower(i)] = true
		}
		if !sLow[strings.ToLower(flow.EgressIntf)] {
			return false
		}
	}
	return true
}

// Rule represents a single ACE or firewall policy rule.
type Rule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Action     string   `json:"action"` // "permit" | "deny" | "unknown"
	Fields     FieldSet `json:"fields"`
	Disabled   bool     `json:"disabled"`
	RawText    string   `json:"raw_text"`
	LineNo     *int     `json:"line_no,omitempty"`
	NATEnabled bool     `json:"nat_enabled"`
	Unresolved []string `json:"unresolved,omitempty"`
}

// RuleSet represents an ordered collection of rules with a default action.
type RuleSet struct {
	Name          string   `json:"name"`
	Kind          string   `json:"kind"` // "acl" | "firewall_policy" | "named-ext" | "named-std" | "standard" | "extended"
	Rules         []Rule   `json:"rules"`
	DefaultAction string   `json:"default_action"`
	Unresolved    []string `json:"unresolved,omitempty"`
}

// Route represents a static or connected route entry.
type Route struct {
	Prefix     string `json:"prefix"`
	PrefixCube Cube   `json:"prefix_cube"`
	NextHop    string `json:"next_hop,omitempty"`
	Interface  string `json:"interface,omitempty"`
	Source     string `json:"source"` // "connected" | "static" | "manual"
	Distance   int    `json:"distance"`
	Metric     int    `json:"metric"`
}

// RouteTable represents a collection of routes supporting longest-prefix match.
type RouteTable struct {
	Routes                 []Route  `json:"routes"`
	DynamicRoutingPresent  bool     `json:"dynamic_routing_present"`
	Protocols              []string `json:"protocols,omitempty"`
}

func (rt RouteTable) Lookup(dstIP string) *Route {
	ipVal, err := IPToInt(dstIP)
	if err != nil {
		return nil
	}
	var bestMatch *Route
	bestPrefixLen := -1

	for i := range rt.Routes {
		r := &rt.Routes[i]
		if r.PrefixCube.ContainsIP(ipVal) {
			pLen := 0
			if p := MaskToPrefixLen(r.PrefixCube.Mask); p != nil {
				pLen = *p
			}
			if pLen > bestPrefixLen {
				bestPrefixLen = pLen
				bestMatch = r
			} else if pLen == bestPrefixLen && bestMatch != nil {
				if r.Source == "connected" && bestMatch.Source != "connected" {
					bestMatch = r
				} else if r.Distance < bestMatch.Distance {
					bestMatch = r
				}
			}
		}
	}
	return bestMatch
}

func (rt RouteTable) ConnectedSubnets() []Route {
	var out []Route
	for _, r := range rt.Routes {
		if r.Source == "connected" {
			out = append(out, r)
		}
	}
	return out
}

// Step represents a single evaluation step in the trace chain.
type Step struct {
	Kind     string `json:"kind"` // acl_in | route | acl_out | policy | skipped_policy | note
	ACL      string `json:"acl,omitempty"`
	Matched  string `json:"matched,omitempty"`
	Action   string `json:"action"` // permit | deny | unknown | skip
	RuleID   string `json:"rule_id,omitempty"`
	RawText  string `json:"raw_text,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	NextHop  string `json:"next_hop,omitempty"`
	Egress   string `json:"egress,omitempty"`
	Source   string `json:"source,omitempty"`
	Note     string `json:"note,omitempty"`
}

func (s Step) ToMap() map[string]any {
	m := map[string]any{
		"kind":   s.Kind,
		"action": s.Action,
	}
	if s.ACL != "" {
		m["acl"] = s.ACL
	}
	if s.Matched != "" {
		m["matched"] = s.Matched
	}
	if s.RuleID != "" {
		m["rule_id"] = s.RuleID
	}
	if s.RawText != "" {
		m["raw_text"] = s.RawText
	}
	if s.Prefix != "" {
		m["prefix"] = s.Prefix
	}
	if s.NextHop != "" {
		m["next_hop"] = s.NextHop
	}
	if s.Egress != "" {
		m["egress"] = s.Egress
	}
	if s.Source != "" {
		m["source"] = s.Source
	}
	if s.Note != "" {
		m["note"] = s.Note
	}
	return m
}

// Trace represents the full path verdict and evaluation steps.
type Trace struct {
	Verdict               string         `json:"verdict"` // "PERMIT" | "DENY" | "UNKNOWN"
	Steps                 []Step         `json:"steps"`
	ImplicitDeny          bool           `json:"implicit_deny"`
	DynamicRoutingPresent bool           `json:"dynamic_routing_present"`
	Unresolved            []string       `json:"unresolved"`
	NATApplied            bool           `json:"nat_applied"`
	Flow                  map[string]any `json:"flow,omitempty"`
}

func (t Trace) ToMap() map[string]any {
	var steps []map[string]any
	for _, s := range t.Steps {
		steps = append(steps, s.ToMap())
	}
	// Dedup unresolved
	seen := make(map[string]bool)
	var deduped []string
	for _, u := range t.Unresolved {
		if !seen[u] {
			seen[u] = true
			deduped = append(deduped, u)
		}
	}
	if deduped == nil {
		deduped = []string{}
	}
	return map[string]any{
		"verdict":                 t.Verdict,
		"steps":                   steps,
		"implicit_deny":           t.ImplicitDeny,
		"dynamic_routing_present": t.DynamicRoutingPresent,
		"unresolved":              deduped,
		"nat_applied":             t.NATApplied,
		"flow":                    t.Flow,
	}
}

// Finding represents a static finding on an ACL or policy configuration.
type Finding struct {
	Key            string         `json:"key"` // shadowed | unreachable | any_any | route_to_nowhere | unresolved_object
	Severity       string         `json:"severity"` // high | medium | low | info
	RuleID         string         `json:"rule_id,omitempty"`
	ACLName        string         `json:"acl_name,omitempty"`
	Params         map[string]any `json:"params,omitempty"`
	MessageKey     string         `json:"message_key"`
	Witness        map[string]any `json:"witness,omitempty"`
	ExpectedRuleID string         `json:"expected_rule_id,omitempty"`
}

func (f Finding) ToMap() map[string]any {
	msgKey := f.MessageKey
	if msgKey == "" {
		msgKey = fmt.Sprintf("finding.%s", f.Key)
	}
	m := map[string]any{
		"key":         f.Key,
		"severity":    f.Severity,
		"message_key": msgKey,
	}
	if f.Witness != nil {
		m["witness"] = f.Witness
	}
	if f.ExpectedRuleID != "" {
		m["expected_rule_id"] = f.ExpectedRuleID
	}
	if f.RuleID != "" {
		m["rule_id"] = f.RuleID
	}
	if f.ACLName != "" {
		m["acl_name"] = f.ACLName
	}
	if f.Params != nil {
		m["params"] = f.Params
	} else {
		m["params"] = map[string]any{}
	}
	return m
}
