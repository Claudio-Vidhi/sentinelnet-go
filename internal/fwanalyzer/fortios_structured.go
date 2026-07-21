package fwanalyzer

import (
	"regexp"
	"sort"
	"strings"
)

// Analisi strutturata FortiOS: la vista interfacce/policy/validazione che
// analyze_device restituisce, distinta dall'envelope a sezioni. Porta di
// analyze_fortios_config.
//
// Vive qui, non in configanalyzer, perché usa le primitive dell'albero
// FortiOS (non esportate): tenerla accanto evita di esporle. Differenza
// organizzativa dal Python, non di comportamento.

type FortiInterface struct {
	Name        string   `json:"name"`
	IP          string   `json:"ip"`
	Allowaccess []string `json:"allowaccess"`
	Vdom        string   `json:"vdom"`
	Role        string   `json:"role"`
	Description string   `json:"description"`
	Vlanid      string   `json:"vlanid"`
	Parent      string   `json:"parent"`
	Status      string   `json:"status"`
}

type FortiVlan struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Parent string `json:"parent"`
	IP     string `json:"ip"`
}

type FortiPolicy struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Srcintf    []string `json:"srcintf"`
	Dstintf    []string `json:"dstintf"`
	Srcaddr    []string `json:"srcaddr"`
	Dstaddr    []string `json:"dstaddr"`
	Service    []string `json:"service"`
	Action     string   `json:"action"`
	Schedule   string   `json:"schedule"`
	Nat        string   `json:"nat"`
	Status     string   `json:"status"`
	Logtraffic string   `json:"logtraffic"`
}

type FortiAddress struct {
	Name    string `json:"name"`
	Subnet  string `json:"subnet"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
}

type FortiNamedMembers struct {
	Name   string   `json:"name"`
	Member []string `json:"member"`
}

type FortiService struct {
	Name         string `json:"name"`
	TCPPortrange string `json:"tcp-portrange"`
	UDPPortrange string `json:"udp-portrange"`
	Protocol     string `json:"protocol"`
}

type FortiVIP struct {
	Name       string `json:"name"`
	Extip      string `json:"extip"`
	Mappedip   string `json:"mappedip"`
	Extintf    string `json:"extintf"`
	Extport    string `json:"extport"`
	Mappedport string `json:"mappedport"`
}

type FortiStaticRoute struct {
	Seq      string `json:"seq"`
	Prefix   string `json:"prefix"`
	NextHop  string `json:"next_hop"`
	Device   string `json:"device"`
	Distance string `json:"distance"`
}

type FortiInsecureMgmt struct {
	Name        string   `json:"name"`
	Allowaccess []string `json:"allowaccess"`
}

type FortiValidation struct {
	AnyAnyPolicies         []string            `json:"any_any_policies"`
	DisabledPolicies       []string            `json:"disabled_policies"`
	UnloggedPolicies       []string            `json:"unlogged_policies"`
	UnusedAddresses        []string            `json:"unused_addresses"`
	UnusedAddrGroups       []string            `json:"unused_addr_groups"`
	UnusedServices         []string            `json:"unused_services"`
	InsecureMgmtInterfaces []FortiInsecureMgmt `json:"insecure_mgmt_interfaces"`
	AdminsWithoutTrusthost []string            `json:"admins_without_trusthost"`
	LoggingDisabled        bool                `json:"logging_disabled"`
}

// FortiOSAnalysis è il risultato strutturato. Hostname è estratto ma
// analyze_device lo sposta nel meta: qui resta per parità con il Python.
type FortiOSAnalysis struct {
	Hostname      string              `json:"hostname"`
	Interfaces    []FortiInterface    `json:"interfaces"`
	Vlans         []FortiVlan         `json:"vlans"`
	Policies      []FortiPolicy       `json:"policies"`
	Addresses     []FortiAddress      `json:"addresses"`
	AddrGroups    []FortiNamedMembers `json:"addr_groups"`
	Services      []FortiService      `json:"services"`
	ServiceGroups []FortiNamedMembers `json:"service_groups"`
	Vips          []FortiVIP          `json:"vips"`
	Routing       FortiRouting        `json:"routing"`
	VPN           FortiVPN            `json:"vpn"`
	Validation    FortiValidation     `json:"validation"`
}

type FortiRouting struct {
	Static []FortiStaticRoute `json:"static"`
}

type FortiVPN struct {
	Phase1 []string `json:"phase1"`
	Phase2 []string `json:"phase2"`
}

var reFortiLogSetting = regexp.MustCompile(`^log\b.*\bsetting$`)

// ss garantisce una slice non-nil: il Python emette [] per le liste vuote, non
// null, e il confronto col golden lo richiede.
func ss(x []string) []string {
	if x == nil {
		return []string{}
	}
	return x
}

// AnalyzeFortiOSStructured ritorna la vista strutturata di una config FortiOS.
// Pura e tollerante.
func AnalyzeFortiOSStructured(content string) FortiOSAnalysis {
	root := fortiTree(content)
	res := FortiOSAnalysis{
		Interfaces:    []FortiInterface{},
		Vlans:         []FortiVlan{},
		Policies:      []FortiPolicy{},
		Addresses:     []FortiAddress{},
		AddrGroups:    []FortiNamedMembers{},
		Services:      []FortiService{},
		ServiceGroups: []FortiNamedMembers{},
		Vips:          []FortiVIP{},
		Routing:       FortiRouting{Static: []FortiStaticRoute{}},
		VPN:           FortiVPN{Phase1: []string{}, Phase2: []string{}},
	}

	if glob := root.get("system global"); glob != nil {
		res.Hostname = glob.set1("hostname", "")
	}

	// Interfacce (+ VLAN)
	for _, c := range root.childrenOf("system interface") {
		n := c.node
		iface := FortiInterface{
			Name:        c.name,
			IP:          n.ipCidr(),
			Allowaccess: ss(n.sets["allowaccess"]),
			Vdom:        n.set1("vdom", ""),
			Role:        n.set1("role", ""),
			Description: n.set1("description", ""),
			Vlanid:      n.set1("vlanid", ""),
			Parent:      n.set1("interface", ""),
			Status:      n.set1("status", "up"),
		}
		res.Interfaces = append(res.Interfaces, iface)
		if iface.Vlanid != "" {
			res.Vlans = append(res.Vlans, FortiVlan{
				ID: iface.Vlanid, Name: c.name, Parent: iface.Parent, IP: iface.IP,
			})
		}
	}

	// Policy
	for _, c := range root.childrenOf("firewall policy") {
		n := c.node
		res.Policies = append(res.Policies, FortiPolicy{
			ID:         c.name,
			Name:       n.set1("name", ""),
			Srcintf:    ss(n.sets["srcintf"]),
			Dstintf:    ss(n.sets["dstintf"]),
			Srcaddr:    ss(n.sets["srcaddr"]),
			Dstaddr:    ss(n.sets["dstaddr"]),
			Service:    ss(n.sets["service"]),
			Action:     n.set1("action", "deny"),
			Schedule:   n.set1("schedule", ""),
			Nat:        n.set1("nat", "disable"),
			Status:     n.set1("status", "enable"),
			Logtraffic: n.set1("logtraffic", ""),
		})
	}

	// Oggetti
	for _, c := range root.childrenOf("firewall address") {
		n := c.node
		res.Addresses = append(res.Addresses, FortiAddress{
			Name: c.name, Subnet: n.set1("subnet", ""),
			Type: n.set1("type", ""), Comment: n.set1("comment", ""),
		})
	}
	for _, c := range root.childrenOf("firewall addrgrp") {
		res.AddrGroups = append(res.AddrGroups, FortiNamedMembers{
			Name: c.name, Member: ss(c.node.sets["member"]),
		})
	}
	for _, c := range root.childrenOf("firewall service custom") {
		n := c.node
		res.Services = append(res.Services, FortiService{
			Name: c.name, TCPPortrange: n.set1("tcp-portrange", ""),
			UDPPortrange: n.set1("udp-portrange", ""), Protocol: n.set1("protocol", ""),
		})
	}
	for _, c := range root.childrenOf("firewall service group") {
		res.ServiceGroups = append(res.ServiceGroups, FortiNamedMembers{
			Name: c.name, Member: ss(c.node.sets["member"]),
		})
	}
	for _, c := range root.childrenOf("firewall vip") {
		n := c.node
		res.Vips = append(res.Vips, FortiVIP{
			Name: c.name, Extip: n.set1("extip", ""), Mappedip: n.set1("mappedip", ""),
			Extintf: n.set1("extintf", ""), Extport: n.set1("extport", ""),
			Mappedport: n.set1("mappedport", ""),
		})
	}

	// Rotte statiche
	for _, c := range root.childrenOf("router static") {
		n := c.node
		dst := n.sets["dst"]
		prefix := ipAddrToCidr(dst)
		if prefix == "" {
			prefix = strings.Join(dst, " ")
		}
		if prefix == "" {
			prefix = "0.0.0.0/0"
		}
		res.Routing.Static = append(res.Routing.Static, FortiStaticRoute{
			Seq: c.name, Prefix: prefix, NextHop: n.set1("gateway", ""),
			Device: n.set1("device", ""), Distance: n.set1("distance", ""),
		})
	}

	// VPN IPsec (nomi fase1 / fase2)
	for _, sec := range []string{"vpn ipsec phase1-interface", "vpn ipsec phase1"} {
		for _, c := range root.childrenOf(sec) {
			res.VPN.Phase1 = append(res.VPN.Phase1, c.name)
		}
	}
	for _, sec := range []string{"vpn ipsec phase2-interface", "vpn ipsec phase2"} {
		for _, c := range root.childrenOf(sec) {
			res.VPN.Phase2 = append(res.VPN.Phase2, c.name)
		}
	}

	res.Validation = fortiValidation(root, res)
	return res
}

func fortiValidation(root *fortiNode, res FortiOSAnalysis) FortiValidation {
	v := FortiValidation{
		AnyAnyPolicies:         []string{},
		DisabledPolicies:       []string{},
		UnloggedPolicies:       []string{},
		InsecureMgmtInterfaces: []FortiInsecureMgmt{},
		AdminsWithoutTrusthost: []string{},
	}

	hasAll := func(addrs []string) bool {
		for _, a := range addrs {
			if strings.EqualFold(a, "all") {
				return true
			}
		}
		return false
	}
	for _, p := range res.Policies {
		label := p.ID
		if p.Name != "" {
			label = p.ID + " (" + p.Name + ")"
		}
		if p.Action == "accept" && hasAll(p.Srcaddr) && hasAll(p.Dstaddr) {
			v.AnyAnyPolicies = append(v.AnyAnyPolicies, label)
		}
		if p.Status == "disable" {
			v.DisabledPolicies = append(v.DisabledPolicies, label)
		}
		if p.Logtraffic == "disable" {
			v.UnloggedPolicies = append(v.UnloggedPolicies, label)
		}
	}

	usedAddr := map[string]bool{}
	usedSvc := map[string]bool{}
	for _, p := range res.Policies {
		for _, a := range p.Srcaddr {
			usedAddr[strings.ToLower(a)] = true
		}
		for _, a := range p.Dstaddr {
			usedAddr[strings.ToLower(a)] = true
		}
		for _, s := range p.Service {
			usedSvc[strings.ToLower(s)] = true
		}
	}
	for _, g := range res.AddrGroups {
		for _, m := range g.Member {
			usedAddr[strings.ToLower(m)] = true
		}
	}
	for _, g := range res.ServiceGroups {
		for _, m := range g.Member {
			usedSvc[strings.ToLower(m)] = true
		}
	}
	vipNames := map[string]bool{}
	for _, vip := range res.Vips {
		vipNames[strings.ToLower(vip.Name)] = true
	}

	for _, a := range res.Addresses {
		low := strings.ToLower(a.Name)
		if !usedAddr[low] && low != "all" {
			v.UnusedAddresses = append(v.UnusedAddresses, a.Name)
		}
	}
	for _, s := range res.Services {
		low := strings.ToLower(s.Name)
		if !usedSvc[low] && low != "all" {
			v.UnusedServices = append(v.UnusedServices, s.Name)
		}
	}
	for _, g := range res.AddrGroups {
		low := strings.ToLower(g.Name)
		if !usedAddr[low] && !vipNames[low] {
			v.UnusedAddrGroups = append(v.UnusedAddrGroups, g.Name)
		}
	}
	sort.Strings(v.UnusedAddresses)
	sort.Strings(v.UnusedServices)
	sort.Strings(v.UnusedAddrGroups)
	v.UnusedAddresses = ss(v.UnusedAddresses)
	v.UnusedServices = ss(v.UnusedServices)
	v.UnusedAddrGroups = ss(v.UnusedAddrGroups)

	// Accesso di management insicuro (http/telnet)
	for _, i := range res.Interfaces {
		var bad []string
		for _, a := range i.Allowaccess {
			if strings.EqualFold(a, "http") || strings.EqualFold(a, "telnet") {
				bad = append(bad, a)
			}
		}
		if len(bad) > 0 {
			v.InsecureMgmtInterfaces = append(v.InsecureMgmtInterfaces,
				FortiInsecureMgmt{Name: i.Name, Allowaccess: bad})
		}
	}

	// Admin senza trusthost
	for _, c := range root.childrenOf("system admin") {
		hasTrust := false
		for k := range c.node.sets {
			if strings.HasPrefix(k, "trusthost") {
				hasTrust = true
				break
			}
		}
		if !hasTrust {
			v.AdminsWithoutTrusthost = append(v.AdminsWithoutTrusthost, c.name)
		}
	}

	// Logging: almeno una sezione 'log ... setting' con status enable
	loggingEnabled := false
	for _, c := range root.children {
		if reFortiLogSetting.MatchString(c.name) && c.node.set1("status", "") == "enable" {
			loggingEnabled = true
			break
		}
	}
	v.LoggingDisabled = !loggingEnabled
	return v
}
