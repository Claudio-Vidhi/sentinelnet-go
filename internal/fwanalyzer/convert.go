package fwanalyzer

import (
	"fmt"
	"regexp"
	"strings"
)

// Converter deterministici (preview) fra vendor firewall. Porta di
// convert_config e dei due _convert_*_to_* del Python.
//
// Best-effort: mappano gli elementi riconosciuti e riportano il resto come
// "unmapped" (stanza/riga grezza), così l'operatore vede cosa non è stato
// tradotto invece di una conversione silenziosamente parziale.

// ConvItem è un elemento tradotto: sorgente, risultato e una nota.
type ConvItem struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Note   string `json:"note"`
}

// ConvertResult è l'esito di una conversione.
type ConvertResult struct {
	Mapped      []ConvItem `json:"mapped"`
	Unmapped    []string   `json:"unmapped"`
	PreviewText string     `json:"preview_text"`
}

var firewallVendors = map[string]bool{"fortios": true, "panos": true}

// ConvertConfig converte fra 'fortios' e 'panos'. Errore su vendor non validi
// o coincidenti, con gli stessi messaggi del Python.
func ConvertConfig(sourceText, sourceVendor, targetVendor string) (ConvertResult, error) {
	sv := strings.ToLower(strings.TrimSpace(sourceVendor))
	tv := strings.ToLower(strings.TrimSpace(targetVendor))
	if !firewallVendors[sv] || !firewallVendors[tv] {
		return ConvertResult{}, fmt.Errorf(
			"Vendor non supportato: '%s' -> '%s' (solo vendor firewall supportati: [fortios panos])",
			sourceVendor, targetVendor)
	}
	if sv == tv {
		return ConvertResult{}, fmt.Errorf("Vendor sorgente e destinazione coincidono.")
	}

	var mapped []ConvItem
	var unmapped []string
	if sv == "fortios" {
		mapped, unmapped = convertFortiOSToPanos(sourceText)
	} else {
		mapped, unmapped = convertPanosToFortiOS(sourceText)
	}

	comment := "!"
	if tv == "fortios" {
		comment = "#"
	}
	header := fmt.Sprintf(
		"%s Anteprima conversione %s -> %s — SentinelNet Config Converter\n"+
			"%s %d elementi mappati, %d non mappati (vedi elenco 'unmapped').\n",
		comment, sv, tv, comment, len(mapped), len(unmapped))
	targets := make([]string, len(mapped))
	for i, m := range mapped {
		targets[i] = m.Target
	}
	preview := header + "\n" + strings.Join(targets, "\n\n") + "\n"

	if mapped == nil {
		mapped = []ConvItem{}
	}
	if unmapped == nil {
		unmapped = []string{}
	}
	return ConvertResult{Mapped: mapped, Unmapped: unmapped, PreviewText: preview}, nil
}

// fortiRenderStanza ricostruisce il testo di una stanza FortiOS dal nodo.
func fortiRenderStanza(section, key string, n *fortiNode) string {
	lines := []string{"config " + section, `    edit "` + key + `"`}
	for _, k := range n.setOrder {
		vals := n.sets[k]
		parts := make([]string, len(vals))
		for i, v := range vals {
			if strings.Contains(v, " ") || v == "" {
				parts[i] = `"` + v + `"`
			} else {
				parts[i] = v
			}
		}
		line := "        set " + k + " " + strings.Join(parts, " ")
		lines = append(lines, strings.TrimRight(line, " "))
	}
	lines = append(lines, "    next", "end")
	return strings.Join(lines, "\n")
}

// setsOr replica n["sets"].get(key, def): il default vale solo se la chiave è
// assente, non se è presente ma vuota.
func setsOr(n *fortiNode, key string, def ...string) []string {
	if v, ok := n.sets[key]; ok {
		return v
	}
	return def
}

func convertFortiOSToPanos(src string) ([]ConvItem, []string) {
	root := fortiTree(src)
	var mapped []ConvItem
	var unmapped []string
	handled := map[string]bool{
		"system interface": true, "router static": true, "firewall address": true,
		"firewall service custom": true, "firewall policy": true, "system global": true,
	}

	// Interfacce
	for _, c := range root.childrenOf("system interface") {
		n := c.node
		s := fortiRenderStanza("system interface", c.name, n)
		cidr := n.ipCidr()
		if cidr == "" {
			unmapped = append(unmapped, s)
			continue
		}
		lines := []string{"set network interface ethernet " + c.name + " layer3 ip " + cidr}
		note := ""
		desc := n.set1("description", "")
		if desc == "" {
			desc = n.set1("alias", "")
		}
		if desc != "" {
			lines = append(lines, `set address-object `+c.name+`-desc comment "`+desc+`"`)
			note = "descrizione riportata come commento separato (PAN-OS non ha description sull'interfaccia L3)"
		}
		if strings.ToLower(n.set1("status", "up")) == "down" {
			if note != "" {
				note += "; "
			}
			note += "interfaccia down: disabilitare manualmente in PAN-OS"
		}
		mapped = append(mapped, ConvItem{s, strings.Join(lines, "\n"), note})
	}

	// Address objects
	for _, c := range root.childrenOf("firewall address") {
		n := c.node
		s := fortiRenderStanza("firewall address", c.name, n)
		subnet := n.sets["subnet"]
		atype := n.set1("type", "ipmask")
		if (atype != "ipmask" && atype != "") || len(subnet) < 2 {
			unmapped = append(unmapped, s)
			continue
		}
		cidr := ipAddrToCidr(subnet)
		if cidr == "" {
			unmapped = append(unmapped, s)
			continue
		}
		mapped = append(mapped, ConvItem{s, "set address " + c.name + " ip-netmask " + cidr, ""})
	}

	// Servizi
	for _, c := range root.childrenOf("firewall service custom") {
		n := c.node
		s := fortiRenderStanza("firewall service custom", c.name, n)
		tcp := n.sets["tcp-portrange"]
		udp := n.sets["udp-portrange"]
		switch {
		case len(tcp) > 0:
			mapped = append(mapped, ConvItem{s, "set service " + c.name + " protocol tcp port " + tcp[0], ""})
		case len(udp) > 0:
			mapped = append(mapped, ConvItem{s, "set service " + c.name + " protocol udp port " + udp[0], ""})
		default:
			unmapped = append(unmapped, s)
		}
	}

	// Rotte statiche
	for _, c := range root.childrenOf("router static") {
		n := c.node
		s := fortiRenderStanza("router static", c.name, n)
		dst := n.sets["dst"]
		if len(dst) == 0 {
			dst = []string{"0.0.0.0", "0.0.0.0"}
		}
		cidr := ipAddrToCidr(dst)
		if cidr == "" {
			cidr = dst[0] + "/0"
		}
		gw := n.set1("gateway", "")
		dev := n.set1("device", "")
		if gw == "" {
			unmapped = append(unmapped, s)
			continue
		}
		rname := "route-" + c.name
		lines := []string{
			"set network virtual-router default routing-table ip static-route " + rname + " destination " + cidr,
			"set network virtual-router default routing-table ip static-route " + rname + " nexthop ip-address " + gw,
		}
		note := ""
		if dev != "" {
			note = "interfaccia in uscita FortiOS '" + dev + "' non riportata (PAN-OS usa il virtual-router)"
		}
		mapped = append(mapped, ConvItem{s, strings.Join(lines, "\n"), note})
	}

	// Policy
	for _, c := range root.childrenOf("firewall policy") {
		n := c.node
		s := fortiRenderStanza("firewall policy", c.name, n)
		name := n.set1("name", "")
		if name == "" {
			name = "rule" + c.name
		}
		srcintf := setsOr(n, "srcintf", "any")
		dstintf := setsOr(n, "dstintf", "any")
		srcaddr := setsOr(n, "srcaddr", "any")
		dstaddr := setsOr(n, "dstaddr", "any")
		service := setsOr(n, "service", "any")
		action := "deny"
		if n.set1("action", "deny") == "accept" {
			action = "allow"
		}
		var lines []string
		for _, z := range srcintf {
			lines = append(lines, `set rulebase security rules "`+name+`" from `+z)
		}
		for _, z := range dstintf {
			lines = append(lines, `set rulebase security rules "`+name+`" to `+z)
		}
		for _, a := range srcaddr {
			lines = append(lines, `set rulebase security rules "`+name+`" source `+a)
		}
		for _, a := range dstaddr {
			lines = append(lines, `set rulebase security rules "`+name+`" destination `+a)
		}
		for _, sv := range service {
			lines = append(lines, `set rulebase security rules "`+name+`" service `+sv)
		}
		lines = append(lines, `set rulebase security rules "`+name+`" action `+action)
		note := ""
		if n.set1("nat", "disable") == "enable" {
			lines = append(lines, `set rulebase nat rules "`+name+`" from `+srcintf[0])
			lines = append(lines, `set rulebase nat rules "`+name+`" to `+dstintf[0])
			note = "NAT abilitato: regola NAT creata come anteprima separata, verificare source-translation"
		}
		mapped = append(mapped, ConvItem{s, strings.Join(lines, "\n"), note})
	}

	// Sezioni non gestite -> unmapped (stanza grezza)
	for _, c := range root.children {
		if handled[c.name] {
			continue
		}
		if len(c.node.children) > 0 {
			for _, child := range c.node.children {
				unmapped = append(unmapped, fortiRenderStanza(c.name, child.name, child.node))
			}
		} else if len(c.node.setOrder) > 0 {
			raw := fortiRenderStanza(c.name, "", c.node)
			raw = strings.ReplaceAll(raw, "    edit \"\"\n", "")
			raw = strings.ReplaceAll(raw, "    next\n", "")
			unmapped = append(unmapped, raw)
		}
	}
	return mapped, unmapped
}

var (
	reConvIface = regexp.MustCompile(`(?i)^network\s+interface\s+ethernet\s+(\S+)\s+layer3\s+ip\s+(\S+)$`)
	reConvSvc   = regexp.MustCompile(`(?i)^service\s+(\S+)\s+protocol\s+(tcp|udp)\s+port\s+(\S+)$`)
	reConvRoute = regexp.MustCompile(`(?i)^network\s+virtual-router\s+(\S+)\s+routing-table\s+ip\s+static-route\s+(\S+)\s+(destination|nexthop)\s+(?:ip-address\s+)?(\S+)$`)
)

func convertPanosToFortiOS(src string) ([]ConvItem, []string) {
	lines := panosLines(src)
	var mapped []ConvItem
	var unmapped []string
	consumed := map[string]bool{}

	// Interfacce L3
	for _, ln := range lines {
		m := reConvIface.FindStringSubmatch(strings.Join(ln.toks, " "))
		if m == nil {
			continue
		}
		name, cidr := m[1], m[2]
		ip, mask := cidrSplit(cidr)
		if ip == "" {
			unmapped = append(unmapped, ln.raw)
			consumed[ln.raw] = true
			continue
		}
		target := "config system interface\n    edit \"" + name + "\"\n" +
			"        set ip " + ip + " " + mask + "\n    next\nend"
		mapped = append(mapped, ConvItem{ln.raw, target, ""})
		consumed[ln.raw] = true
	}

	// Address objects
	for _, e := range panosCollect(lines, "address") {
		cidr := e.attr("ip-netmask")
		if cidr == "" {
			unmapped = append(unmapped, e.raw...)
			markConsumed(consumed, e.raw)
			continue
		}
		ip, mask := cidrSplit(cidr)
		if ip == "" {
			unmapped = append(unmapped, e.raw...)
			markConsumed(consumed, e.raw)
			continue
		}
		target := "config firewall address\n    edit \"" + e.name + "\"\n" +
			"        set subnet " + ip + " " + mask + "\n    next\nend"
		mapped = append(mapped, ConvItem{strings.Join(e.raw, "\n"), target, ""})
		markConsumed(consumed, e.raw)
	}

	// Servizi
	for _, ln := range lines {
		m := reConvSvc.FindStringSubmatch(strings.Join(ln.toks, " "))
		if m == nil {
			continue
		}
		name, proto, port := m[1], strings.ToLower(m[2]), m[3]
		target := "config firewall service custom\n    edit \"" + name + "\"\n" +
			"        set " + proto + "-portrange " + port + "\n    next\nend"
		mapped = append(mapped, ConvItem{ln.raw, target, ""})
		consumed[ln.raw] = true
	}

	// Rotte statiche
	type routeEntry struct {
		destination, nexthop string
		raw                  []string
	}
	var routeOrder []string
	routeByName := map[string]*routeEntry{}
	for _, ln := range lines {
		m := reConvRoute.FindStringSubmatch(strings.Join(ln.toks, " "))
		if m == nil {
			continue
		}
		rname := m[2]
		e := routeByName[rname]
		if e == nil {
			e = &routeEntry{}
			routeByName[rname] = e
			routeOrder = append(routeOrder, rname)
		}
		if strings.EqualFold(m[3], "destination") {
			e.destination = m[4]
		} else {
			e.nexthop = m[4]
		}
		e.raw = append(e.raw, ln.raw)
	}
	seq := 0
	for _, rname := range routeOrder {
		seq++
		e := routeByName[rname]
		markConsumed(consumed, e.raw)
		if e.destination == "" || e.nexthop == "" {
			unmapped = append(unmapped, e.raw...)
			continue
		}
		net, mask := cidrSplit(e.destination)
		if net == "" {
			unmapped = append(unmapped, e.raw...)
			continue
		}
		target := fmt.Sprintf("config router static\n    edit %d\n"+
			"        set dst %s %s\n        set gateway %s\n    next\nend",
			seq, net, mask, e.nexthop)
		mapped = append(mapped, ConvItem{strings.Join(e.raw, "\n"), target, ""})
	}

	// Policy (security rules)
	natRules := map[string]panosEntry{}
	for _, e := range panosCollect(lines, "rulebase", "nat", "rules") {
		natRules[e.name] = e
	}
	seq = 0
	for _, e := range panosCollect(lines, "rulebase", "security", "rules") {
		seq++
		markConsumed(consumed, e.raw)
		srcintf := orAny(e.attrAll("from"))
		dstintf := orAny(e.attrAll("to"))
		srcaddr := orAny(e.attrAll("source"))
		dstaddr := orAny(e.attrAll("destination"))
		service := e.attrAll("service")
		if len(service) == 0 {
			service = []string{"ALL"}
		}
		action := "deny"
		if strings.EqualFold(e.attr("action"), "allow") {
			action = "accept"
		}
		out := []string{
			"config firewall policy", fmt.Sprintf("    edit %d", seq),
			`        set name "` + e.name + `"`,
			"        set srcintf " + quoteJoin(srcintf),
			"        set dstintf " + quoteJoin(dstintf),
			"        set srcaddr " + quoteJoin(srcaddr),
			"        set dstaddr " + quoteJoin(dstaddr),
			"        set service " + quoteJoin(service),
			"        set action " + action,
		}
		note := ""
		if nat, ok := natRules[e.name]; ok {
			out = append(out, "        set nat enable")
			markConsumed(consumed, nat.raw)
			note = "regola NAT associata rilevata: source-translation non riportata, verificare manualmente"
		}
		out = append(out, "    next", "end")
		mapped = append(mapped, ConvItem{strings.Join(e.raw, "\n"), strings.Join(out, "\n"), note})
	}

	// Righe non riconosciute
	for _, ln := range lines {
		if !consumed[ln.raw] {
			unmapped = append(unmapped, ln.raw)
		}
	}
	return mapped, unmapped
}

func markConsumed(set map[string]bool, raws []string) {
	for _, r := range raws {
		set[r] = true
	}
}

func orAny(v []string) []string {
	if len(v) == 0 {
		return []string{"any"}
	}
	return v
}

func quoteJoin(vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = `"` + v + `"`
	}
	return strings.Join(parts, " ")
}
