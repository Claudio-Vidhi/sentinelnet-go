package fwanalyzer

import (
	"regexp"
	"strings"
)

// Analizzatore PAN-OS (Palo Alto) in formato "set" CLI.
//
// Limite noto (v1, come il Python): solo il formato set-CLI. Le config
// esportate in XML non sono gestite.

var rePanosToken = regexp.MustCompile(`"[^"]*"|\S+`)

// panosTokens tokenizza una riga rispettando le stringhe tra apici.
func panosTokens(s string) []string {
	raw := rePanosToken.FindAllString(s, -1)
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

// panosLine è una riga "set" già tokenizzata (senza il "set" iniziale). raw è
// la riga originale ripulita, che serve ai converter per riportare la sorgente.
type panosLine struct {
	toks []string
	raw  string
}

// panosLines ritorna le righe che iniziano con "set ", tokenizzate.
func panosLines(text string) []panosLine {
	var out []panosLine
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || !strings.HasPrefix(strings.ToLower(s), "set ") {
			continue
		}
		out = append(out, panosLine{toks: panosTokens(s[4:]), raw: s})
	}
	return out
}

// panosEntry raccoglie le "parts" (token dopo il nome) di un oggetto e le
// righe grezze che lo compongono.
type panosEntry struct {
	name  string
	parts [][]string
	raw   []string
}

// panosCollect raggruppa le righe il cui path inizia con prefix e ha un nome
// subito dopo. L'ordine di prima apparizione è conservato (il dict Python lo
// mantiene, e le sezioni lo espongono così).
func panosCollect(lines []panosLine, prefix ...string) []panosEntry {
	n := len(prefix)
	var order []*panosEntry
	byName := map[string]*panosEntry{}
	for _, ln := range lines {
		if len(ln.toks) <= n {
			continue
		}
		match := true
		for i := 0; i < n; i++ {
			if !strings.EqualFold(ln.toks[i], prefix[i]) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		name := ln.toks[n]
		e := byName[name]
		if e == nil {
			e = &panosEntry{name: name}
			byName[name] = e
			order = append(order, e)
		}
		if rest := ln.toks[n+1:]; len(rest) > 0 {
			e.parts = append(e.parts, rest)
		}
		e.raw = append(e.raw, ln.raw)
	}
	out := make([]panosEntry, len(order))
	for i, e := range order {
		out[i] = *e
	}
	return out
}

// values estrae i valori dopo path da una entry, gestendo le liste tra
// parentesi quadre "[ a b c ]" e i valori singoli.
func (e panosEntry) values(path ...string) []string {
	plen := len(path)
	var out []string
	for _, part := range e.parts {
		if len(part) <= plen {
			continue
		}
		match := true
		for i := 0; i < plen; i++ {
			if !strings.EqualFold(part[i], path[i]) {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		rest := part[plen:]
		if len(rest) > 0 && rest[0] == "[" {
			for _, tok := range rest[1:] {
				if tok == "]" {
					break
				}
				out = append(out, tok)
			}
		} else {
			out = append(out, rest...)
		}
	}
	return out
}

func (e panosEntry) first(path ...string) string {
	if vals := e.values(path...); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// attr ritorna il primo valore dell'attributo a un solo token (part[0]==attr),
// senza gestione delle liste tra parentesi. È l'_panos_attr del Python, usato
// dai converter dove i valori sono singoli.
func (e panosEntry) attr(attr string) string {
	for _, p := range e.parts {
		if len(p) > 1 && strings.EqualFold(p[0], attr) {
			return p[1]
		}
	}
	return ""
}

// attrAll ritorna tutti i valori dell'attributo a un solo token.
func (e panosEntry) attrAll(attr string) []string {
	var out []string
	for _, p := range e.parts {
		if len(p) > 1 && strings.EqualFold(p[0], attr) {
			out = append(out, p[1])
		}
	}
	return out
}

// serverAddr: "server <SRV> address <IP>" (o ip-address/host) -> primo IP.
func (e panosEntry) serverAddr() string {
	for _, p := range e.parts {
		if len(p) >= 4 && strings.EqualFold(p[0], "server") {
			switch strings.ToLower(p[2]) {
			case "address", "ip-address", "host":
				return p[3]
			}
		}
	}
	return ""
}

// AnalyzePanos ritorna l'envelope a sezioni per una config PAN-OS set-CLI.
// Puro e tollerante: su input strano ritorna {vendor: "panos", sections: []}.
func AnalyzePanos(text string) Envelope {
	lines := panosLines(text)
	sections := []Section{}

	// 1) Address objects
	rows := []map[string]string{}
	for _, e := range panosCollect(lines, "address") {
		atype, val := "ip-netmask", e.first("ip-netmask")
		if val == "" {
			for _, t := range []string{"ip-range", "fqdn", "ip-wildcard"} {
				if v := e.first(t); v != "" {
					atype, val = t, v
					break
				}
			}
		}
		rows = append(rows, map[string]string{"name": e.name, "type": atype, "value": val})
	}
	sections = append(sections, section("addresses", []string{"name", "type", "value"}, rows))

	// 2) Address groups
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "address-group") {
		members := e.values("static")
		if len(members) == 0 {
			members = e.values("dynamic", "filter")
		}
		rows = append(rows, map[string]string{"name": e.name, "members": join(members)})
	}
	sections = append(sections, section("address_groups", []string{"name", "members"}, rows))

	// 3) Services
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "service") {
		proto := ""
		if len(e.values("protocol", "tcp")) > 0 {
			proto = "tcp"
		} else if len(e.values("protocol", "udp")) > 0 {
			proto = "udp"
		}
		port := e.first("protocol", "tcp", "port")
		if port == "" {
			port = e.first("protocol", "udp", "port")
		}
		rows = append(rows, map[string]string{"name": e.name, "protocol": proto, "port": port})
	}
	sections = append(sections, section("services", []string{"name", "protocol", "port"}, rows))

	// 4) Service groups
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "service-group") {
		rows = append(rows, map[string]string{"name": e.name, "members": join(e.values("members"))})
	}
	sections = append(sections, section("service_groups", []string{"name", "members"}, rows))

	// 5) Security rules
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "rulebase", "security", "rules") {
		rows = append(rows, map[string]string{
			"name":        e.name,
			"from":        join(e.values("from")),
			"to":          join(e.values("to")),
			"source":      join(e.values("source")),
			"destination": join(e.values("destination")),
			"application": join(e.values("application")),
			"service":     join(e.values("service")),
			"action":      e.first("action"),
		})
	}
	sections = append(sections, section("security_rules",
		[]string{"name", "from", "to", "source", "destination", "application", "service", "action"}, rows))

	// 6) NAT rules
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "rulebase", "nat", "rules") {
		translation := e.first("source-translation", "dynamic-ip-and-port", "translated-address")
		if translation == "" {
			translation = e.first("source-translation", "static-ip", "translated-address")
		}
		if translation == "" {
			translation = e.first("destination-translation", "translated-address")
		}
		rows = append(rows, map[string]string{
			"name":        e.name,
			"from":        join(e.values("from")),
			"to":          join(e.values("to")),
			"source":      join(e.values("source")),
			"destination": join(e.values("destination")),
			"service":     e.first("service"),
			"translation": translation,
		})
	}
	sections = append(sections, section("nat_rules",
		[]string{"name", "from", "to", "source", "destination", "service", "translation"}, rows))

	// 7) Zones
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "zone") {
		ifaces := e.values("network", "layer3")
		if len(ifaces) == 0 {
			ifaces = e.values("network", "layer2")
		}
		if len(ifaces) == 0 {
			ifaces = e.values("network", "tap")
		}
		rows = append(rows, map[string]string{"name": e.name, "interfaces": join(ifaces)})
	}
	sections = append(sections, section("zones", []string{"name", "interfaces"}, rows))

	// 8) VPN (IKE gateway + tunnel IPsec)
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "network", "ike", "gateway") {
		peer := e.first("peer-address", "ip")
		if peer == "" {
			peer = e.first("peer-address", "fqdn")
		}
		rows = append(rows, map[string]string{
			"name": e.name, "kind": "ike-gateway", "peer": peer,
			"interface": e.first("local-address", "interface"),
		})
	}
	for _, e := range panosCollect(lines, "network", "tunnel", "ipsec") {
		rows = append(rows, map[string]string{
			"name": e.name, "kind": "ipsec-tunnel",
			"peer":      e.first("auto-key", "ike-gateway"),
			"interface": e.first("tunnel-interface"),
		})
	}
	sections = append(sections, section("vpn_ipsec", []string{"name", "kind", "peer", "interface"}, rows))

	// 9) Administrators
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "mgt-config", "users") {
		role := ""
		if e.first("permissions", "role-based", "superuser") != "" {
			role = "superuser"
		} else {
			role = e.first("permissions", "role-based", "custom", "profile")
		}
		if role == "" {
			role = "custom"
		}
		rows = append(rows, map[string]string{"name": e.name, "role": role})
	}
	sections = append(sections, section("administrators", []string{"name", "role"}, rows))

	// 10) Authentication
	rows = []map[string]string{}
	for _, e := range panosCollect(lines, "shared", "authentication-profile") {
		rows = append(rows, map[string]string{
			"name": e.name, "kind": "auth-profile", "server": e.first("method"),
		})
	}
	for _, proto := range []string{"radius", "tacplus", "ldap"} {
		for _, e := range panosCollect(lines, "shared", "server-profile", proto) {
			server := e.serverAddr()
			if server == "" {
				server = e.first("server")
			}
			rows = append(rows, map[string]string{"name": e.name, "kind": proto, "server": server})
		}
	}
	sections = append(sections, section("authentication", []string{"name", "kind", "server"}, rows))

	return Envelope{Vendor: "panos", Sections: sections}
}
