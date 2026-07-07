// Package configanalyzer analizza le running-config Cisco IOS/IOS-XE raccolte
// come backup, per estrarne una vista strutturata (VLAN, Routing/VPN, ACL,
// Interfacce) + validazione incrociata degli oggetti (ACL/VLAN inutilizzati,
// riferimenti mancanti).
//
// Porting fedele di config_analyzer.py: il modulo e' volutamente tollerante e
// non deve MAI sollevare panic su config strane o parziali. AnalyzeConfig e'
// pura (nessun I/O) ed e' quindi facilmente testabile; AnalyzeDevice/AnalyzeAll
// aggiungono la lettura del backup piu' recente e lo scoping per sede/tenant.
package configanalyzer

import (
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// --- Strutture del contratto JSON (chiavi identiche a FastAPI) ---------------

type SVI struct {
	IP       string `json:"ip"`
	Shutdown bool   `json:"shutdown"`
}

type Vlan struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	SVI          *SVI     `json:"svi"`
	AccessIfaces []string `json:"access_ifaces"`
	TrunkIfaces  []string `json:"trunk_ifaces"`
}

type Interface struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Mode         string `json:"mode"`
	AccessVlan   string `json:"access_vlan"`
	VoiceVlan    string `json:"voice_vlan"`
	TrunkAllowed string `json:"trunk_allowed"`
	TrunkNative  string `json:"trunk_native"`
	IP           string `json:"ip"`
	AclIn        string `json:"acl_in"`
	AclOut       string `json:"acl_out"`
	Shutdown     bool   `json:"shutdown"`
	ChannelGroup string `json:"channel_group"`
	Raw          string `json:"raw"`
}

type StaticRoute struct {
	Prefix  string  `json:"prefix"`
	NextHop string  `json:"next_hop"`
	AD      *string `json:"ad"`
	Name    string  `json:"name"`
	VRF     string  `json:"vrf"`
}

type Protocol struct {
	Proto   string   `json:"proto"`
	ID      string   `json:"id"`
	Details []string `json:"details"`
	Raw     string   `json:"raw"`
}

type VRF struct {
	Name       string   `json:"name"`
	RD         string   `json:"rd"`
	Interfaces []string `json:"interfaces"`
}

type Routing struct {
	Static    []StaticRoute `json:"static"`
	Protocols []Protocol    `json:"protocols"`
	VRFs      []VRF         `json:"vrfs"`
}

type AclEntry struct {
	Seq    string `json:"seq"`
	Action string `json:"action"`
	Text   string `json:"text"`
}

type AclApplied struct {
	Where     string `json:"where"`
	Target    string `json:"target"`
	Direction string `json:"direction"`
}

type Acl struct {
	Name    string       `json:"name"`
	Kind    string       `json:"kind"`
	Entries []AclEntry   `json:"entries"`
	Applied []AclApplied `json:"applied"`
}

type VPN struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Raw  string `json:"raw"`
}

type MissingAcl struct {
	Name         string `json:"name"`
	ReferencedIn string `json:"referenced_in"`
}

type UndefinedVlan struct {
	Vlan         string `json:"vlan"`
	ReferencedIn string `json:"referenced_in"`
}

type RouteAclRef struct {
	Context string `json:"context"`
	Acl     string `json:"acl"`
}

type Validation struct {
	UnusedAcls     []string        `json:"unused_acls"`
	MissingAcls    []MissingAcl    `json:"missing_acls"`
	UnusedVlans    []string        `json:"unused_vlans"`
	UndefinedVlans []UndefinedVlan `json:"undefined_vlans"`
	RouteAclRefs   []RouteAclRef   `json:"route_acl_refs"`
}

type Analysis struct {
	Vlans      []Vlan      `json:"vlans"`
	Interfaces []Interface `json:"interfaces"`
	Routing    Routing     `json:"routing"`
	Acls       []Acl       `json:"acls"`
	VPN        []VPN       `json:"vpn"`
	Validation Validation  `json:"validation"`
}

type VTPStatus struct {
	Mode   string `json:"mode"`
	Domain string `json:"domain"`
}

// DeviceResult = Analysis + meta (ip/hostname/tenant/vtp), come da contratto.
type DeviceResult struct {
	Analysis
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname"`
	Tenant   string    `json:"tenant"`
	VTP      VTPStatus `json:"vtp"`
}

// aclRef: riferimento interno a un ACL (per la validazione).
type aclRef struct {
	name      string
	where     string
	target    string
	direction string
	context   string
	routing   bool
}

// --- Utility di basso livello ------------------------------------------------

// maskToPrefix converte una subnet mask dotted (255.255.255.0) in lunghezza /nn.
// Ritorna -1 se non e' una mask valida.
func maskToPrefix(mask string) int {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return -1
	}
	total := 0
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return -1
		}
		total += bits.OnesCount(uint(v))
	}
	return total
}

// ipAddrToCidr: da ['10.1.10.1','255.255.255.0'] ricava 'a.b.c.d/nn'. '' se ko.
func ipAddrToCidr(tokens []string) string {
	if len(tokens) >= 2 {
		ip := tokens[0]
		if pfx := maskToPrefix(tokens[1]); pfx >= 0 {
			return ip + "/" + strconv.Itoa(pfx)
		}
		if strings.HasPrefix(tokens[1], "/") {
			return ip + tokens[1]
		}
	}
	if len(tokens) == 1 && strings.Contains(tokens[0], "/") {
		return tokens[0]
	}
	return ""
}

// expandVlanList espande '10,20,30-35' in ['10','20','30','31',...]. Tollerante.
func expandVlanList(spec string) []string {
	out := []string{}
	if spec == "" {
		return out
	}
	spec = strings.ReplaceAll(spec, " ", "")
	for _, chunk := range strings.Split(spec, ",") {
		if chunk == "" {
			continue
		}
		if strings.Contains(chunk, "-") {
			ab := strings.SplitN(chunk, "-", 2)
			a, err1 := strconv.Atoi(ab[0])
			b, err2 := strconv.Atoi(ab[1])
			if err1 != nil || err2 != nil {
				continue
			}
			if a <= b && (b-a) < 5000 {
				for x := a; x <= b; x++ {
					out = append(out, strconv.Itoa(x))
				}
			}
		} else if isDigits(chunk) {
			out = append(out, chunk)
		}
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// runningConfig ritorna solo la parte 'running-config' del backup, tagliando le
// sezioni appese (=== ... === e --- SHOW ... ---).
func runningConfig(content string) []string {
	lines := []string{}
	for _, ln := range strings.Split(content, "\n") {
		s := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		if strings.HasPrefix(s, "===") || strings.HasPrefix(s, "--- SHOW") {
			break
		}
		lines = append(lines, strings.TrimRight(ln, "\r"))
	}
	return lines
}

var reShowVlanRow = regexp.MustCompile(`(?i)^(\d{1,4})\s+(\S+)\s+(?:active|act/\S+|suspended|sus/\S+)`)
var reShowVlanSection = regexp.MustCompile(`(?is)--- SHOW VLAN ---\s*\n(.*?)(?:\n--- [A-Z]|\n===|$)`)
var reVtpSection = regexp.MustCompile(`(?is)--- SHOW VTP STATUS ---\s*\n(.*?)(?:\n--- [A-Z]|\n===|$)`)
var reVtpMode = regexp.MustCompile(`(?i)VTP Operating Mode\s*:\s*(\S+)`)
var reVtpDomain = regexp.MustCompile(`(?i)VTP Domain Name\s*:\s*(\S+)`)

// ParseShowVlan: VLAN apprese via VTP dalla sezione '--- SHOW VLAN ---'.
func ParseShowVlan(content string) map[string]string {
	out := map[string]string{}
	m := reShowVlanSection.FindStringSubmatch(content)
	if m == nil {
		return out
	}
	for _, ln := range strings.Split(m[1], "\n") {
		row := reShowVlanRow.FindStringSubmatch(strings.TrimSpace(strings.TrimRight(ln, "\r")))
		if row != nil {
			out[row[1]] = row[2]
		}
	}
	return out
}

// ParseVTPStatus estrae mode/domain dalla sezione '--- SHOW VTP STATUS ---'.
func ParseVTPStatus(content string) VTPStatus {
	out := VTPStatus{}
	m := reVtpSection.FindStringSubmatch(content)
	if m == nil {
		return out
	}
	if mm := reVtpMode.FindStringSubmatch(m[1]); mm != nil {
		out.Mode = strings.ToLower(strings.TrimSpace(mm[1]))
	}
	if md := reVtpDomain.FindStringSubmatch(m[1]); md != nil {
		out.Domain = strings.TrimSpace(md[1])
	}
	return out
}

type block struct {
	header string
	body   []string
}

// iterBlocks itera i blocchi top-level della config: una riga a colonna 0 (non
// '!', non vuota) apre un blocco che prosegue con le righe indentate seguenti.
func iterBlocks(lines []string) []block {
	blocks := []block{}
	i, n := 0, len(lines)
	for i < n {
		raw := lines[i]
		stripped := strings.TrimSpace(raw)
		if stripped == "" || stripped == "!" || (len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')) {
			i++
			continue
		}
		header := strings.TrimRight(raw, " \t")
		body := []string{}
		i++
		for i < n {
			nxt := lines[i]
			if len(nxt) > 0 && (nxt[0] == ' ' || nxt[0] == '\t') && strings.TrimSpace(nxt) != "" && strings.TrimSpace(nxt) != "!" {
				body = append(body, strings.TrimRight(nxt, " \t"))
				i++
			} else {
				break
			}
		}
		blocks = append(blocks, block{header, body})
	}
	return blocks
}

// --- Parsing dei singoli oggetti ---------------------------------------------

var reVrfForwarding = regexp.MustCompile(`(?i)^(?:ip\s+)?vrf forwarding (\S+)`)

func parseInterface(header string, body []string) Interface {
	name := ""
	if fields := strings.Fields(header); len(fields) > 1 {
		name = strings.TrimSpace(strings.Join(fields[1:], " "))
	}
	iface := Interface{Name: name, Raw: strings.Join(append([]string{header}, body...), "\n")}
	hasSwitchport := false
	swMode := ""
	for _, b := range body {
		s := strings.TrimSpace(b)
		low := strings.ToLower(s)
		switch {
		case strings.HasPrefix(low, "description "):
			iface.Description = strings.TrimSpace(s[12:])
		case strings.HasPrefix(low, "switchport access vlan "):
			hasSwitchport = true
			iface.AccessVlan = lastField(s)
		case strings.HasPrefix(low, "switchport voice vlan "):
			hasSwitchport = true
			iface.VoiceVlan = lastField(s)
		case strings.HasPrefix(low, "switchport trunk allowed vlan "):
			hasSwitchport = true
			val := strings.TrimSpace(strings.SplitN(s, "vlan", 2)[1])
			val = strings.TrimSpace(strings.ReplaceAll(val, "add ", ""))
			if iface.TrunkAllowed != "" {
				iface.TrunkAllowed = strings.Trim(iface.TrunkAllowed+","+val, ",")
			} else {
				iface.TrunkAllowed = val
			}
		case strings.HasPrefix(low, "switchport trunk native vlan "):
			hasSwitchport = true
			iface.TrunkNative = lastField(s)
		case strings.HasPrefix(low, "switchport mode "):
			hasSwitchport = true
			swMode = lastField(s)
		case low == "switchport" || strings.HasPrefix(low, "switchport "):
			hasSwitchport = true
		case strings.HasPrefix(low, "ip address ") || strings.HasPrefix(low, "ipv4 address "):
			toks := strings.Fields(s)
			if !strings.Contains(low, "secondary") {
				if len(toks) >= 4 {
					if cidr := ipAddrToCidr(toks[2:4]); cidr != "" {
						iface.IP = cidr
					}
				}
			}
		case strings.HasPrefix(low, "ip access-group "):
			toks := strings.Fields(s)
			if len(toks) >= 4 {
				if toks[len(toks)-1] == "in" {
					iface.AclIn = toks[2]
				} else if toks[len(toks)-1] == "out" {
					iface.AclOut = toks[2]
				}
			}
		case low == "shutdown":
			iface.Shutdown = true
		case strings.HasPrefix(low, "channel-group "):
			f := strings.Fields(s)
			if len(f) > 1 {
				iface.ChannelGroup = f[1]
			}
		}
	}
	// Determinazione modo
	nm := strings.ToLower(name)
	switch {
	case strings.HasPrefix(nm, "vlan"):
		iface.Mode = "svi"
	case swMode == "trunk" || iface.TrunkAllowed != "" || iface.TrunkNative != "":
		iface.Mode = "trunk"
	case swMode == "access" || iface.AccessVlan != "" || iface.VoiceVlan != "":
		iface.Mode = "access"
	case iface.IP != "":
		iface.Mode = "routed"
	case hasSwitchport:
		iface.Mode = "access"
	case iface.Shutdown:
		iface.Mode = "shutdown-only"
	default:
		iface.Mode = ""
	}
	return iface
}

func lastField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[len(f)-1]
}

func parseStaticRoute(line string) (StaticRoute, bool) {
	toks := strings.Fields(line)
	if len(toks) < 2 {
		return StaticRoute{}, false
	}
	rest := toks[2:]
	vrf := ""
	if len(rest) >= 2 && rest[0] == "vrf" {
		vrf = rest[1]
		rest = rest[2:]
	}
	if len(rest) < 3 {
		return StaticRoute{}, false
	}
	net, mask, nexthop := rest[0], rest[1], rest[2]
	prefix := net + " " + mask
	if pfx := maskToPrefix(mask); pfx >= 0 {
		prefix = net + "/" + strconv.Itoa(pfx)
	}
	tail := rest[3:]
	name := ""
	var ad *string
	// name <...>
	for idx, t := range tail {
		if t == "name" {
			name = strings.TrimSpace(strings.Join(tail[idx+1:], " "))
			tail = tail[:idx]
			break
		}
	}
	for _, t := range tail {
		if isDigits(t) {
			v := t
			ad = &v
			break
		}
	}
	return StaticRoute{Prefix: prefix, NextHop: nexthop, AD: ad, Name: name, VRF: vrf}, true
}

var reDistList = regexp.MustCompile(`(?i)^distribute-list\s+(?:prefix\s+)?(\S+)\s+(in|out)`)

func parseRouterBlock(header string, body []string) (Protocol, [][2]string) {
	toks := strings.Fields(header)
	proto, id := "", ""
	if len(toks) > 1 {
		proto = toks[1]
	}
	if len(toks) > 2 {
		id = toks[2]
	}
	details := []string{}
	distRefs := [][2]string{}
	for _, b := range body {
		s := strings.TrimSpace(b)
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "network ") || strings.HasPrefix(low, "neighbor ") ||
			strings.HasPrefix(low, "redistribute ") || strings.HasPrefix(low, "distribute-list ") {
			details = append(details, s)
		}
		if strings.HasPrefix(low, "distribute-list ") {
			if m := reDistList.FindStringSubmatch(low); m != nil {
				distRefs = append(distRefs, [2]string{m[1], m[2]})
			}
		}
	}
	return Protocol{Proto: proto, ID: id, Details: details, Raw: strings.Join(append([]string{header}, body...), "\n")}, distRefs
}

// --- Analisi principale (pura, testabile) ------------------------------------

var (
	reVlanDef       = regexp.MustCompile(`(?i)^vlan (\d[\d,\-]*)\s*$`)
	reVrfDef        = regexp.MustCompile(`(?i)^(?:ip vrf|vrf definition) (\S+)`)
	reAclNum        = regexp.MustCompile(`(?i)^access-list (\d+) (.*)$`)
	reAclNamed      = regexp.MustCompile(`(?i)^ip access-list (standard|extended) (\S+)`)
	reAclSeq        = regexp.MustCompile(`^(\d+)\s+(.*)$`)
	reAccessClass   = regexp.MustCompile(`(?i)^access-class (\S+) (in|out)`)
	reRouteMap      = regexp.MustCompile(`(?i)^route-map (\S+)(?:\s+(permit|deny)\s+(\d+))?`)
	reMatchIP       = regexp.MustCompile(`(?i)^match ip address (?:prefix-list )?(.+)$`)
	reSnmpCommunity = regexp.MustCompile(`(?i)^snmp-server community (\S+)(?:\s+(ro|rw))?(?:\s+(\S+))?`)
	reNatList       = regexp.MustCompile(`(?i)^ip nat inside source list (\S+)`)
	reHostname      = regexp.MustCompile(`(?m)^hostname (\S+)`)
)

// AnalyzeConfig analizza il testo di una running-config e ritorna la struttura
// del contratto (senza i campi meta ip/hostname/tenant, aggiunti a valle).
func AnalyzeConfig(content string) Analysis {
	lines := runningConfig(content)

	interfaces := []Interface{}
	svis := map[string]*SVI{}
	vlanDefs := map[string]string{}
	vlanDefOrder := []string{}
	staticRoutes := []StaticRoute{}
	protocols := []Protocol{}
	vrfOrder := []string{}
	vrfs := map[string]*VRF{}
	aclOrder := []string{}
	acls := map[string]*Acl{}
	aclRefs := []aclRef{}
	vpn := []VPN{}

	accessUseOrder := []string{}
	accessUse := map[string]string{}
	usedVlans := map[string]bool{}

	getVrf := func(name string) *VRF {
		if v, ok := vrfs[name]; ok {
			return v
		}
		v := &VRF{Name: name, Interfaces: []string{}}
		vrfs[name] = v
		vrfOrder = append(vrfOrder, name)
		return v
	}
	getAcl := func(name, kind string) *Acl {
		if a, ok := acls[name]; ok {
			return a
		}
		a := &Acl{Name: name, Kind: kind, Entries: []AclEntry{}}
		acls[name] = a
		aclOrder = append(aclOrder, name)
		return a
	}

	for _, blk := range iterBlocks(lines) {
		header := blk.header
		body := blk.body
		low := strings.ToLower(header)

		// --- Interfacce ---
		if strings.HasPrefix(low, "interface ") {
			iface := parseInterface(header, body)
			interfaces = append(interfaces, iface)
			nm := iface.Name
			nml := strings.ToLower(nm)
			if strings.HasPrefix(nml, "vlan") {
				vid := strings.TrimSpace(nm[4:])
				if isDigits(vid) {
					svis[vid] = &SVI{IP: iface.IP, Shutdown: iface.Shutdown}
					usedVlans[vid] = true
				}
			}
			if iface.AccessVlan != "" {
				usedVlans[iface.AccessVlan] = true
				if _, ok := accessUse[iface.AccessVlan]; !ok {
					accessUse[iface.AccessVlan] = nm + " (access)"
					accessUseOrder = append(accessUseOrder, iface.AccessVlan)
				}
			}
			if iface.VoiceVlan != "" {
				usedVlans[iface.VoiceVlan] = true
				if _, ok := accessUse[iface.VoiceVlan]; !ok {
					accessUse[iface.VoiceVlan] = nm + " (voice)"
					accessUseOrder = append(accessUseOrder, iface.VoiceVlan)
				}
			}
			for _, v := range expandVlanList(iface.TrunkAllowed) {
				usedVlans[v] = true
			}
			if iface.AclIn != "" {
				aclRefs = append(aclRefs, aclRef{name: iface.AclIn, where: "interface", target: nm, direction: "in", context: "interface " + nm + " (in)"})
			}
			if iface.AclOut != "" {
				aclRefs = append(aclRefs, aclRef{name: iface.AclOut, where: "interface", target: nm, direction: "out", context: "interface " + nm + " (out)"})
			}
			for _, b := range body {
				if m := reVrfForwarding.FindStringSubmatch(strings.TrimSpace(b)); m != nil {
					vname := lastField(strings.TrimSpace(b))
					v := getVrf(vname)
					v.Interfaces = append(v.Interfaces, nm)
				}
			}
			if strings.HasPrefix(nml, "tunnel") {
				vpn = append(vpn, VPN{Kind: "tunnel", Name: nm, Raw: strings.Join(append([]string{header}, body...), "\n")})
			}
			continue
		}

		// --- VLAN definitions ---
		if m := reVlanDef.FindStringSubmatch(header); m != nil &&
			!strings.HasPrefix(low, "vlan configuration") && !strings.HasPrefix(low, "vlan internal") {
			ids := expandVlanList(m[1])
			name := ""
			for _, b := range body {
				bs := strings.TrimSpace(b)
				if strings.HasPrefix(strings.ToLower(bs), "name ") {
					name = strings.TrimSpace(bs[5:])
				}
			}
			for _, vid := range ids {
				if _, ok := vlanDefs[vid]; !ok {
					vlanDefOrder = append(vlanDefOrder, vid)
				}
				if len(ids) == 1 {
					vlanDefs[vid] = name
				} else if _, ok := vlanDefs[vid]; !ok {
					vlanDefs[vid] = ""
				}
			}
			continue
		}

		// --- Static routes ---
		if strings.HasPrefix(low, "ip route ") {
			if r, ok := parseStaticRoute(strings.TrimSpace(header)); ok {
				staticRoutes = append(staticRoutes, r)
			}
			continue
		}

		// --- Router blocks ---
		if strings.HasPrefix(low, "router ") {
			pinfo, distRefs := parseRouterBlock(strings.TrimSpace(header), body)
			protocols = append(protocols, pinfo)
			ctx := strings.TrimSpace("router " + pinfo.Proto + " " + pinfo.ID)
			for _, dr := range distRefs {
				aclRefs = append(aclRefs, aclRef{name: dr[0], where: "route-map", target: ctx, direction: dr[1], context: "distribute-list in " + ctx, routing: true})
			}
			continue
		}

		// --- VRF ---
		if m := reVrfDef.FindStringSubmatch(low); m != nil {
			vname := lastField(strings.TrimSpace(header))
			v := getVrf(vname)
			for _, b := range body {
				bs := strings.TrimSpace(b)
				if strings.HasPrefix(strings.ToLower(bs), "rd ") {
					v.RD = strings.TrimSpace(bs[3:])
				}
			}
			continue
		}

		// --- ACL numerati ---
		if m := reAclNum.FindStringSubmatch(strings.TrimSpace(header)); m != nil {
			num := m[1]
			rest := strings.TrimSpace(m[2])
			n, _ := strconv.Atoi(num)
			kind := "extended"
			if (n >= 1 && n <= 99) || (n >= 1300 && n <= 1999) {
				kind = "standard"
			}
			acl := getAcl(num, kind)
			action := ""
			if f := strings.Fields(rest); len(f) > 0 {
				action = f[0]
			}
			acl.Entries = append(acl.Entries, AclEntry{Seq: "", Action: action, Text: rest})
			continue
		}

		// --- ACL nominali ---
		if m := reAclNamed.FindStringSubmatch(low); m != nil {
			kind := "named-ext"
			if m[1] == "standard" {
				kind = "named-std"
			}
			aname := lastField(strings.TrimSpace(header))
			acl := getAcl(aname, kind)
			acl.Kind = kind
			for _, b := range body {
				bs := strings.TrimSpace(b)
				seq, txt := "", bs
				if mm := reAclSeq.FindStringSubmatch(bs); mm != nil {
					seq, txt = mm[1], mm[2]
				}
				action := ""
				if f := strings.Fields(txt); len(f) > 0 {
					action = f[0]
				}
				acl.Entries = append(acl.Entries, AclEntry{Seq: seq, Action: action, Text: txt})
			}
			continue
		}

		// --- line vty/con: access-class ---
		if strings.HasPrefix(low, "line ") {
			for _, b := range body {
				if mm := reAccessClass.FindStringSubmatch(strings.TrimSpace(b)); mm != nil {
					dir := strings.ToLower(mm[2])
					aclRefs = append(aclRefs, aclRef{name: mm[1], where: "line", target: strings.TrimSpace(header)[5:], direction: dir, context: strings.TrimSpace(header) + " (access-class " + dir + ")"})
				}
			}
			continue
		}

		// --- route-map: match ip address ---
		if m := reRouteMap.FindStringSubmatch(low); m != nil {
			rmname := ""
			if f := strings.Fields(strings.TrimSpace(header)); len(f) > 1 {
				rmname = f[1]
			}
			seq := m[3]
			ctx := strings.TrimSpace("route-map " + rmname + " seq " + seq)
			for _, b := range body {
				if mm := reMatchIP.FindStringSubmatch(strings.TrimSpace(b)); mm != nil {
					for _, acl := range strings.Fields(mm[1]) {
						aclRefs = append(aclRefs, aclRef{name: acl, where: "route-map", target: rmname, direction: "", context: ctx, routing: true})
					}
				}
			}
			continue
		}

		// --- crypto (VPN best-effort) ---
		if strings.HasPrefix(low, "crypto map ") {
			toks := strings.Fields(strings.TrimSpace(header))
			nm := ""
			if len(toks) > 2 {
				nm = toks[2]
			}
			vpn = append(vpn, VPN{Kind: "crypto-map", Name: nm, Raw: strings.Join(append([]string{header}, body...), "\n")})
			continue
		}
		if strings.HasPrefix(low, "crypto isakmp") {
			toks := strings.Fields(strings.TrimSpace(header))
			nm := ""
			if len(toks) > 2 {
				nm = toks[len(toks)-1]
			}
			vpn = append(vpn, VPN{Kind: "isakmp", Name: nm, Raw: strings.Join(append([]string{header}, body...), "\n")})
			continue
		}
		if strings.HasPrefix(low, "crypto ipsec profile") || strings.HasPrefix(low, "crypto ipsec transform-set") {
			toks := strings.Fields(strings.TrimSpace(header))
			nm := ""
			if len(toks) > 0 {
				nm = toks[len(toks)-1]
			}
			vpn = append(vpn, VPN{Kind: "ipsec-profile", Name: nm, Raw: strings.Join(append([]string{header}, body...), "\n")})
			continue
		}

		// --- snmp community con ACL ---
		if mm := reSnmpCommunity.FindStringSubmatch(low); mm != nil && mm[3] != "" {
			acl := lastField(strings.TrimSpace(header))
			aclRefs = append(aclRefs, aclRef{name: acl, where: "snmp", target: mm[1], direction: "", context: "snmp-server community " + mm[1]})
			continue
		}
		// --- ip nat inside source list ---
		if mm := reNatList.FindStringSubmatch(low); mm != nil {
			f := strings.Fields(strings.TrimSpace(header))
			if len(f) > 5 {
				acl := f[5]
				aclRefs = append(aclRefs, aclRef{name: acl, where: "nat", target: "nat", direction: "", context: "ip nat inside source list"})
			}
			continue
		}
	}

	// --- Costruzione vista VLAN ---
	vtpVlans := ParseShowVlan(content)
	allVidsSet := map[string]bool{}
	for v := range vlanDefs {
		allVidsSet[v] = true
	}
	for v := range svis {
		allVidsSet[v] = true
	}
	for v := range vtpVlans {
		if usedVlans[v] {
			allVidsSet[v] = true
		}
	}
	accessByVlan := map[string][]string{}
	trunkByVlan := map[string][]string{}
	for _, iface := range interfaces {
		if iface.Mode == "access" && iface.AccessVlan != "" {
			accessByVlan[iface.AccessVlan] = append(accessByVlan[iface.AccessVlan], iface.Name)
		}
		for _, v := range expandVlanList(iface.TrunkAllowed) {
			trunkByVlan[v] = append(trunkByVlan[v], iface.Name)
		}
	}
	allVids := make([]string, 0, len(allVidsSet))
	for v := range allVidsSet {
		allVids = append(allVids, v)
	}
	sortNumeric(allVids)
	vlans := []Vlan{}
	for _, vid := range allVids {
		name := vlanDefs[vid]
		if name == "" {
			name = vtpVlans[vid]
		}
		vlans = append(vlans, Vlan{
			ID:           vid,
			Name:         name,
			SVI:          svis[vid],
			AccessIfaces: orEmpty(accessByVlan[vid]),
			TrunkIfaces:  orEmpty(trunkByVlan[vid]),
		})
	}

	// --- Validazione ---
	appliedNames := map[string]bool{}
	for _, r := range aclRefs {
		appliedNames[r.name] = true
	}
	for _, name := range aclOrder {
		acl := acls[name]
		applied := []AclApplied{}
		for _, r := range aclRefs {
			if r.name == name {
				applied = append(applied, AclApplied{Where: r.where, Target: r.target, Direction: r.direction})
			}
		}
		acl.Applied = applied
	}

	unusedAcls := []string{}
	for _, name := range aclOrder {
		if !appliedNames[name] {
			unusedAcls = append(unusedAcls, name)
		}
	}
	sort.Strings(unusedAcls)

	missingAcls := []MissingAcl{}
	seenMissing := map[string]bool{}
	definedAcls := map[string]bool{}
	for _, n := range aclOrder {
		definedAcls[n] = true
	}
	for _, r := range aclRefs {
		if !definedAcls[r.name] && !seenMissing[r.name] {
			seenMissing[r.name] = true
			missingAcls = append(missingAcls, MissingAcl{Name: r.name, ReferencedIn: r.context})
		}
	}

	routeAclRefs := []RouteAclRef{}
	for _, r := range aclRefs {
		if r.routing {
			routeAclRefs = append(routeAclRefs, RouteAclRef{Context: r.context, Acl: r.name})
		}
	}

	// Definite = blocchi vlan locali + SVI + VTP.
	definedVlans := map[string]bool{}
	for v := range allVidsSet {
		definedVlans[v] = true
	}
	for v := range vtpVlans {
		definedVlans[v] = true
	}
	unusedVlans := []string{}
	localDefined := map[string]bool{}
	for v := range vlanDefs {
		localDefined[v] = true
	}
	for v := range svis {
		localDefined[v] = true
	}
	for v := range localDefined {
		if !usedVlans[v] && v != "1" {
			unusedVlans = append(unusedVlans, v)
		}
	}
	sortNumeric(unusedVlans)

	undefinedVlans := []UndefinedVlan{}
	seenUndef := map[string]bool{}
	for _, vid := range accessUseOrder {
		if !definedVlans[vid] && vid != "1" && !seenUndef[vid] {
			seenUndef[vid] = true
			undefinedVlans = append(undefinedVlans, UndefinedVlan{Vlan: vid, ReferencedIn: accessUse[vid]})
		}
	}

	aclList := []Acl{}
	for _, name := range aclOrder {
		aclList = append(aclList, *acls[name])
	}
	vrfList := []VRF{}
	for _, name := range vrfOrder {
		vrfList = append(vrfList, *vrfs[name])
	}

	return Analysis{
		Vlans:      vlans,
		Interfaces: interfaces,
		Routing: Routing{
			Static:    staticRoutes,
			Protocols: protocols,
			VRFs:      vrfList,
		},
		Acls: aclList,
		VPN:  vpn,
		Validation: Validation{
			UnusedAcls:     unusedAcls,
			MissingAcls:    missingAcls,
			UnusedVlans:    unusedVlans,
			UndefinedVlans: undefinedVlans,
			RouteAclRefs:   routeAclRefs,
		},
	}
}

// HostnameFromConfig estrae l'hostname dalla running-config (o "").
func HostnameFromConfig(content string) string {
	if m := reHostname.FindStringSubmatch(content); m != nil {
		return m[1]
	}
	return ""
}

func sortNumeric(s []string) {
	sort.Slice(s, func(i, j int) bool {
		return numOr0(s[i]) < numOr0(s[j])
	})
}

func numOr0(s string) int {
	if isDigits(s) {
		n, _ := strconv.Atoi(s)
		return n
	}
	return 0
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
