package policytest

import (
	"strconv"
	"strings"
)

// BuiltinServiceDef represents a built-in service definition.
type BuiltinServiceDef struct {
	Protos    map[int]bool
	DstPorts  *PortSet
	ICMPTypes map[int]bool
}

var BuiltinAddresses = map[string][]Cube{
	"all":      {CubeAny()},
	"none":     {},
	"all_ipv4": {CubeAny()},
}

func LookupBuiltinAddress(name string) ([]Cube, bool) {
	cubes, ok := BuiltinAddresses[strings.ToLower(strings.TrimSpace(name))]
	return cubes, ok
}

var BuiltinServices = map[string]BuiltinServiceDef{
	"all":      {Protos: nil, DstPorts: nil},
	"all_tcp":  {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1, Hi: 65535}}))},
	"all_udp":  {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1, Hi: 65535}}))},
	"all_icmp": {Protos: map[int]bool{1: true}, DstPorts: nil},
	"ping":     {Protos: map[int]bool{1: true}, DstPorts: nil, ICMPTypes: map[int]bool{8: true}},
	"http":     {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 80, Hi: 80}}))},
	"https":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 443, Hi: 443}}))},
	"ssh":      {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 22, Hi: 22}}))},
	"telnet":   {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 23, Hi: 23}}))},
	"dns":      {Protos: map[int]bool{6: true, 17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 53, Hi: 53}}))},
	"smtp":     {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 25, Hi: 25}}))},
	"smtps":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 465, Hi: 465}}))},
	"ftp":      {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 21, Hi: 21}}))},
	"ftp_get":  {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 21, Hi: 21}}))},
	"ftp_put":  {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 21, Hi: 21}}))},
	"ntp":      {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 123, Hi: 123}}))},
	"snmp":     {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 161, Hi: 162}}))},
	"rdp":      {Protos: map[int]bool{6: true, 17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 3389, Hi: 3389}}))},
	"syslog":   {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 514, Hi: 514}}))},
	"ike":      {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 500, Hi: 500}, {Lo: 4500, Hi: 4500}}))},
	"ldap":     {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 389, Hi: 389}}))},
	"ldaps":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 636, Hi: 636}}))},
	"radius":   {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1812, Hi: 1813}}))},
	"radius-acct": {Protos: map[int]bool{17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1813, Hi: 1813}}))},
	"kerberos": {Protos: map[int]bool{6: true, 17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 88, Hi: 88}}))},
	"imap":     {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 143, Hi: 143}}))},
	"imaps":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 993, Hi: 993}}))},
	"pop3":     {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 110, Hi: 110}}))},
	"pop3s":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 995, Hi: 995}}))},
	"mysql":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 3306, Hi: 3306}}))},
	"mssql":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1433, Hi: 1433}}))},
	"ms-sql":   {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1433, Hi: 1433}}))},
	"oracle":   {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 1521, Hi: 1521}}))},
	"sip":      {Protos: map[int]bool{6: true, 17: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 5060, Hi: 5060}}))},
	"squid":    {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 3128, Hi: 3128}}))},
	"vnc":      {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 5900, Hi: 5900}}))},
	"bgp":      {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 179, Hi: 179}}))},
	"gre":      {Protos: map[int]bool{47: true}, DstPorts: nil},
	"ah":       {Protos: map[int]bool{51: true}, DstPorts: nil},
	"esp":      {Protos: map[int]bool{50: true}, DstPorts: nil},
	"ospf":     {Protos: map[int]bool{89: true}, DstPorts: nil},
	"webaccess": {Protos: map[int]bool{6: true}, DstPorts: ptrPortSet(NewPortSet([]PortInterval{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}}))},
}

func ptrPortSet(ps PortSet) *PortSet {
	return &ps
}

func LookupBuiltinService(name string) (*BuiltinServiceDef, bool) {
	def, ok := BuiltinServices[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, false
	}
	return &def, true
}

// Protocol mappings
var ProtoMap = map[string]*int{
	"ip":    nil,
	"ipv4":  nil,
	"ip4":   nil,
	"any":   nil,
	"all":   nil,
	"icmp":  intPtr(1),
	"igmp":  intPtr(2),
	"tcp":   intPtr(6),
	"udp":   intPtr(17),
	"gre":   intPtr(47),
	"esp":   intPtr(50),
	"ah":    intPtr(51),
	"eigrp": intPtr(88),
	"ospf":  intPtr(89),
	"pim":   intPtr(103),
	"sctp":  intPtr(132),
}

var ProtoNumToName = map[int]string{
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

func intPtr(i int) *int {
	return &i
}

func ProtoFromName(nameOrNum string) *int {
	s := strings.ToLower(strings.TrimSpace(nameOrNum))
	if s == "" {
		return nil
	}
	if p, ok := ProtoMap[s]; ok {
		return p
	}
	if n, err := strconv.Atoi(s); err == nil {
		return &n
	}
	return nil
}

// PortNames maps IOS/common port names to integers.
var PortNames = map[string]int{
	"echo":        7,
	"discard":     9,
	"daytime":     13,
	"chargen":     19,
	"ftp-data":    20,
	"ftp":         21,
	"ssh":         22,
	"telnet":      23,
	"smtp":        25,
	"time":        37,
	"tacacs":      49,
	"domain":      53,
	"dns":         53,
	"bootps":      67,
	"dhcps":       67,
	"bootpc":      68,
	"dhcpc":       68,
	"tftp":        69,
	"gopher":      70,
	"finger":      79,
	"www":         80,
	"http":        80,
	"kerberos":    88,
	"pop2":        109,
	"pop3":        110,
	"sunrpc":      111,
	"ident":       113,
	"nntp":        119,
	"ntp":         123,
	"netbios-ns":  137,
	"netbios-dgm": 138,
	"netbios-ssn": 139,
	"imap":        143,
	"snmp":        161,
	"snmptrap":    162,
	"bgp":         179,
	"ldap":        389,
	"https":       443,
	"ssl":         443,
	"ldaps":       636,
	"syslog":      514,
	"rip":         520,
	"l2tp":        1701,
	"pptp":        1723,
	"radius":      1812,
	"radius-acct": 1813,
	"ms-sql-s":    1433,
	"oracle":      1521,
	"mysql":       3306,
	"rdp":         3389,
	"sip":         5060,
}

func ParsePortVal(tok string) *int {
	s := strings.ToLower(strings.TrimSpace(tok))
	if val, err := strconv.Atoi(s); err == nil {
		if val >= 0 && val <= 65535 {
			return &val
		}
		return nil
	}
	if p, ok := PortNames[s]; ok {
		return &p
	}
	return nil
}

var ICMPTypeNames = map[string]int{
	"echo-reply":           0,
	"unreachable":          3,
	"source-quench":        4,
	"redirect":             5,
	"alternate-address":    6,
	"echo":                 8,
	"router-advertisement": 9,
	"router-solicitation":  10,
	"time-exceeded":        11,
	"parameter-problem":    12,
	"timestamp-request":    13,
	"timestamp-reply":      14,
	"information-request":  15,
	"information-reply":    16,
	"mask-request":         17,
	"mask-reply":           18,
	"traceroute":           30,
	"conversion-error":     31,
	"mobile-redirect":      32,
}

var ICMPCodeNames = map[string]int{
	"net-unreachable":             3,
	"host-unreachable":            3,
	"protocol-unreachable":        3,
	"port-unreachable":            3,
	"packet-too-big":              3,
	"source-route-failed":         3,
	"network-unknown":             3,
	"host-unknown":                3,
	"host-isolated":               3,
	"dod-net-prohibited":          3,
	"dod-host-prohibited":         3,
	"net-tos-unreachable":         3,
	"host-tos-unreachable":        3,
	"administratively-prohibited": 3,
	"host-precedence-unreachable": 3,
	"precedence-unreachable":      3,
	"net-redirect":                5,
	"host-redirect":               5,
	"net-tos-redirect":            5,
	"host-tos-redirect":           5,
	"ttl-exceeded":                11,
	"reassembly-timeout":          11,
	"general-parameter-problem":   12,
	"option-missing":              12,
	"no-room-for-option":          12,
}
