package fwanalyzer

import (
	"regexp"
	"sort"
	"strings"
)

// --- Envelope generico -------------------------------------------------------

// Column è una colonna di una sezione, con la chiave i18n per il frontend.
type Column struct {
	Key      string `json:"key"`
	LabelKey string `json:"label_key"`
}

// Section è una tabella dell'envelope: id, etichetta i18n, colonne e righe.
// Le righe sono mappe stringa->stringa nell'ordine che il frontend rende.
type Section struct {
	ID       string              `json:"id"`
	LabelKey string              `json:"label_key"`
	Columns  []Column            `json:"columns"`
	Rows     []map[string]string `json:"rows"`
}

// Envelope è la risposta di un analizzatore firewall.
type Envelope struct {
	Vendor   string    `json:"vendor"`
	Sections []Section `json:"sections"`
}

func col(key string) Column { return Column{Key: key, LabelKey: "fw.col." + key} }

func section(id string, keys []string, rows []map[string]string) Section {
	cols := make([]Column, len(keys))
	for i, k := range keys {
		cols[i] = col(k)
	}
	if rows == nil {
		rows = []map[string]string{}
	}
	return Section{ID: id, LabelKey: "fw.sec." + id, Columns: cols, Rows: rows}
}

// --- Primitive di parsing FortiOS (config/edit/set/next/end) ------------------

// fortiNode è un nodo dell'albero: i "set" (chiave->valori) e i figli per nome.
// children usa una slice ordinata per preservare l'ordine di apparizione, che
// il Python conserva col dict e che il frontend si aspetta.
type fortiNode struct {
	sets map[string][]string
	// setOrder conserva l'ordine di prima apparizione delle chiavi set: il
	// dict Python lo mantiene, e la sezione vpn_ssl lo espone così com'è.
	setOrder []string
	children []fortiChild
}

type fortiChild struct {
	name string
	node *fortiNode
}

func newFortiNode() *fortiNode {
	return &fortiNode{sets: map[string][]string{}}
}

// child ritorna il figlio con quel nome, creandolo se assente (come setdefault).
func (n *fortiNode) child(name string) *fortiNode {
	for _, c := range n.children {
		if c.name == name {
			return c.node
		}
	}
	child := newFortiNode()
	n.children = append(n.children, fortiChild{name: name, node: child})
	return child
}

// get naviga per nome sezione (es. "firewall policy"); nil se assente.
func (n *fortiNode) get(path string) *fortiNode {
	for _, c := range n.children {
		if c.name == path {
			return c.node
		}
	}
	return nil
}

// set1 ritorna il primo valore di un set, oppure def.
func (n *fortiNode) set1(key, def string) string {
	if vals := n.sets[key]; len(vals) > 0 {
		return vals[0]
	}
	return def
}

func (n *fortiNode) ipCidr() string {
	if vals := n.sets["ip"]; len(vals) > 0 {
		return ipAddrToCidr(vals)
	}
	return ""
}

var reFortiToken = regexp.MustCompile(`"[^"]*"|\S+`)

// fortiTokens tokenizza una riga rispettando le stringhe tra doppi apici.
func fortiTokens(s string) []string {
	raw := reFortiToken.FindAllString(s, -1)
	out := make([]string, len(raw))
	for i, t := range raw {
		if len(t) >= 2 && strings.HasPrefix(t, `"`) && strings.HasSuffix(t, `"`) {
			out[i] = t[1 : len(t)-1]
		} else {
			out[i] = t
		}
	}
	return out
}

// fortiTree parsa la struttura a blocchi in un albero. Tollerante a blocchi
// non chiusi o annidamenti anomali.
func fortiTree(content string) *fortiNode {
	root := newFortiNode()
	stack := []*fortiNode{root}
	for _, raw := range strings.Split(content, "\n") {
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		low := strings.ToLower(s)
		top := stack[len(stack)-1]
		switch {
		case strings.HasPrefix(low, "config "):
			name := strings.Trim(strings.TrimSpace(s[7:]), `"`)
			stack = append(stack, top.child(name))
		case strings.HasPrefix(low, "edit "):
			key := strings.Trim(strings.TrimSpace(s[5:]), `"`)
			stack = append(stack, top.child(key))
		case low == "next" || low == "end":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		case strings.HasPrefix(low, "set "):
			toks := fortiTokens(s)
			if len(toks) >= 2 {
				k := strings.ToLower(toks[1])
				if _, seen := top.sets[k]; !seen {
					top.setOrder = append(top.setOrder, k)
				}
				top.sets[k] = toks[2:]
			}
		}
	}
	return root
}

// childrenOf ritorna i figli (in ordine) di una sezione, o nil.
func (n *fortiNode) childrenOf(path string) []fortiChild {
	if node := n.get(path); node != nil {
		return node.children
	}
	return nil
}

// --- Analisi FortiOS ---------------------------------------------------------

var fortiSecretKeys = map[string]bool{
	"passwd": true, "password": true, "psksecret": true, "secret": true,
	"key": true, "private-key": true, "passphrase": true, "auth-pwd": true,
	"ppk-secret": true, "ldap-password": true,
}

const fortiMask = "***REDACTED***"

func join(vals []string) string { return strings.Join(vals, ", ") }

// AnalyzeFortiOS ritorna l'envelope a sezioni per una config FortiOS. Puro e
// tollerante: su input strano ritorna {vendor: "fortios", sections: []}.
func AnalyzeFortiOS(text string) Envelope {
	root := fortiTree(text)
	sections := []Section{}

	// 1) Policy
	rows := []map[string]string{}
	for _, c := range root.childrenOf("firewall policy") {
		n := c.node
		rows = append(rows, map[string]string{
			"id":         c.name,
			"name":       n.set1("name", ""),
			"srcintf":    join(n.sets["srcintf"]),
			"dstintf":    join(n.sets["dstintf"]),
			"srcaddr":    join(n.sets["srcaddr"]),
			"dstaddr":    join(n.sets["dstaddr"]),
			"service":    join(n.sets["service"]),
			"action":     n.set1("action", "deny"),
			"nat":        n.set1("nat", "disable"),
			"status":     n.set1("status", "enable"),
			"schedule":   n.set1("schedule", ""),
			"logtraffic": n.set1("logtraffic", ""),
		})
	}
	sections = append(sections, section("policies",
		[]string{"id", "name", "srcintf", "dstintf", "srcaddr", "dstaddr",
			"service", "action", "nat", "status", "schedule", "logtraffic"}, rows))

	// 2) Address objects
	rows = []map[string]string{}
	for _, c := range root.childrenOf("firewall address") {
		n := c.node
		subnet := ipAddrToCidr(n.sets["subnet"])
		if subnet == "" {
			subnet = n.set1("fqdn", "")
		}
		if subnet == "" {
			subnet = join(append(append([]string{}, n.sets["start-ip"]...), n.sets["end-ip"]...))
		}
		rows = append(rows, map[string]string{
			"name":    c.name,
			"type":    n.set1("type", "ipmask"),
			"subnet":  subnet,
			"comment": n.set1("comment", ""),
		})
	}
	sections = append(sections, section("addresses",
		[]string{"name", "type", "subnet", "comment"}, rows))

	// 3) Address groups
	rows = []map[string]string{}
	for _, c := range root.childrenOf("firewall addrgrp") {
		rows = append(rows, map[string]string{"name": c.name, "members": join(c.node.sets["member"])})
	}
	sections = append(sections, section("address_groups", []string{"name", "members"}, rows))

	// 4) Services (custom)
	rows = []map[string]string{}
	for _, c := range root.childrenOf("firewall service custom") {
		n := c.node
		rows = append(rows, map[string]string{
			"name":          c.name,
			"protocol":      n.set1("protocol", ""),
			"tcp_portrange": join(n.sets["tcp-portrange"]),
			"udp_portrange": join(n.sets["udp-portrange"]),
		})
	}
	sections = append(sections, section("services",
		[]string{"name", "protocol", "tcp_portrange", "udp_portrange"}, rows))

	// 5) Schedules (recurring + onetime)
	rows = []map[string]string{}
	for _, sk := range []struct{ sec, kind string }{
		{"firewall schedule recurring", "recurring"},
		{"firewall schedule onetime", "onetime"},
	} {
		for _, c := range root.childrenOf(sk.sec) {
			n := c.node
			rows = append(rows, map[string]string{
				"name":  c.name,
				"type":  sk.kind,
				"day":   join(n.sets["day"]),
				"start": n.set1("start", ""),
				"end":   n.set1("end", ""),
			})
		}
	}
	sections = append(sections, section("schedules",
		[]string{"name", "type", "day", "start", "end"}, rows))

	// 6) VIP
	rows = []map[string]string{}
	for _, c := range root.childrenOf("firewall vip") {
		n := c.node
		rows = append(rows, map[string]string{
			"name":       c.name,
			"extip":      join(n.sets["extip"]),
			"mappedip":   join(n.sets["mappedip"]),
			"extintf":    n.set1("extintf", ""),
			"extport":    n.set1("extport", ""),
			"mappedport": n.set1("mappedport", ""),
		})
	}
	sections = append(sections, section("vips",
		[]string{"name", "extip", "mappedip", "extintf", "extport", "mappedport"}, rows))

	// 7) IP pools
	rows = []map[string]string{}
	for _, c := range root.childrenOf("firewall ippool") {
		n := c.node
		rows = append(rows, map[string]string{
			"name":    c.name,
			"type":    n.set1("type", "overload"),
			"startip": n.set1("startip", ""),
			"endip":   n.set1("endip", ""),
		})
	}
	sections = append(sections, section("ippools",
		[]string{"name", "type", "startip", "endip"}, rows))

	// 8) Interfaces (+ zona)
	zoneOf := map[string]string{}
	for _, c := range root.childrenOf("system zone") {
		for _, member := range c.node.sets["interface"] {
			zoneOf[member] = c.name
		}
	}
	rows = []map[string]string{}
	for _, c := range root.childrenOf("system interface") {
		n := c.node
		rows = append(rows, map[string]string{
			"name":        c.name,
			"ip":          n.ipCidr(),
			"zone":        zoneOf[c.name],
			"vdom":        n.set1("vdom", ""),
			"allowaccess": join(n.sets["allowaccess"]),
			"status":      n.set1("status", "up"),
		})
	}
	sections = append(sections, section("interfaces",
		[]string{"name", "ip", "zone", "vdom", "allowaccess", "status"}, rows))

	// 9) VPN IPsec (phase1 + phase2 uniti per nome fase1)
	p2ByP1 := map[string][]string{}
	for _, sec := range []string{"vpn ipsec phase2-interface", "vpn ipsec phase2"} {
		for _, c := range root.childrenOf(sec) {
			p1 := c.node.set1("phase1name", "")
			if p1 == "" {
				p1 = c.node.set1("phase1", "")
			}
			p2ByP1[p1] = append(p2ByP1[p1], c.name)
		}
	}
	rows = []map[string]string{}
	for _, sec := range []string{"vpn ipsec phase1-interface", "vpn ipsec phase1"} {
		for _, c := range root.childrenOf(sec) {
			n := c.node
			rows = append(rows, map[string]string{
				"name":      c.name,
				"remote_gw": n.set1("remote-gw", ""),
				"interface": n.set1("interface", ""),
				"proposal":  join(n.sets["proposal"]),
				"phase2":    join(p2ByP1[c.name]),
			})
		}
	}
	sections = append(sections, section("vpn_ipsec",
		[]string{"name", "remote_gw", "interface", "proposal", "phase2"}, rows))

	// 10) VPN SSL settings (chiave/valore, con mascheramento dei segreti)
	rows = []map[string]string{}
	if ssl := root.get("vpn ssl settings"); ssl != nil {
		// Le chiavi vanno nell'ordine di inserimento: il Python itera il dict
		// dei set, che conserva l'ordine. La mappa Go no, quindi si tiene
		// separatamente l'ordine di prima apparizione.
		for _, k := range ssl.setOrder {
			val := join(ssl.sets[k])
			if fortiSecretKeys[k] {
				val = fortiMask
			}
			rows = append(rows, map[string]string{"key": k, "value": val})
		}
	}
	sections = append(sections, section("vpn_ssl", []string{"key", "value"}, rows))

	// 11) Administrators
	rows = []map[string]string{}
	for _, c := range root.childrenOf("system admin") {
		n := c.node
		keys := make([]string, 0, len(n.sets))
		for k := range n.sets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var trusthosts []string
		for _, k := range keys {
			if !strings.HasPrefix(k, "trusthost") && !strings.HasPrefix(k, "ip6-trusthost") {
				continue
			}
			v := strings.Join(n.sets[k], " ")
			if v == "0.0.0.0 0.0.0.0" || v == "::/0" {
				continue
			}
			trusthosts = append(trusthosts, v)
		}
		rows = append(rows, map[string]string{
			"name":        c.name,
			"accprofile":  n.set1("accprofile", ""),
			"trusthost":   join(trusthosts),
			"remote_auth": n.set1("remote-auth", "disable"),
		})
	}
	sections = append(sections, section("administrators",
		[]string{"name", "accprofile", "trusthost", "remote_auth"}, rows))

	// 12) Authentication
	rows = []map[string]string{}
	for _, sk := range []struct{ sec, kind string }{
		{"user radius", "radius"}, {"user tacacs+", "tacacs+"},
		{"user ldap", "ldap"}, {"user fsso", "fsso"},
	} {
		for _, c := range root.childrenOf(sk.sec) {
			n := c.node
			server := n.set1("server", "")
			if server == "" {
				server = n.set1("primary-server", "")
			}
			if server == "" {
				server = n.set1("host", "")
			}
			sso := ""
			if sk.kind == "fsso" {
				sso = "yes"
			}
			rows = append(rows, map[string]string{"name": c.name, "kind": sk.kind, "server": server, "sso": sso})
		}
	}
	for _, c := range root.childrenOf("user group") {
		gtype := c.node.set1("group-type", "")
		sso := ""
		if strings.Contains(strings.ToLower(gtype), "fsso") {
			sso = "yes"
		}
		rows = append(rows, map[string]string{
			"name": c.name, "kind": "group",
			"server": join(c.node.sets["member"]), "sso": sso,
		})
	}
	sections = append(sections, section("authentication",
		[]string{"name", "kind", "server", "sso"}, rows))

	return Envelope{Vendor: "fortios", Sections: sections}
}
