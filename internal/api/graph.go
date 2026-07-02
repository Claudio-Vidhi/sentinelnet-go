package api

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/topology"
)

// Node è il modello unificato usato da /api/network-map e /api/device-classification.
type Node struct {
	ID          string       `json:"id"`
	Label       string       `json:"label"`
	DisplayIP   string       `json:"display_ip"`
	DeviceType  string       `json:"device_type"`
	Subcategory string       `json:"subcategory"`
	Status      string       `json:"status"`
	IsBoundary  bool         `json:"is_boundary"`
	Vendor      string       `json:"vendor"`
	Group       string       `json:"group"`
	Version     string       `json:"version"`
	Model       string       `json:"model"`
	ReportedIP  string       `json:"reported_ip,omitempty"`
	VTPDomain   string       `json:"vtp_domain,omitempty"`
	VTPMode     string       `json:"vtp_mode,omitempty"`
	HAGroup     string       `json:"ha_group,omitempty"`
	Discovered  bool         `json:"discovered"`
	IsManual    bool         `json:"is_manual"`
	NameOptions []nameOption `json:"name_options,omitempty"`
}

type nameOption struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Link struct {
	Source       string   `json:"source"`
	Target       string   `json:"target"`
	LocalPort    string   `json:"local_port"`
	RemotePort   string   `json:"remote_port"`
	IsPortChannel bool    `json:"is_portchannel"`
	PCName       string   `json:"pc_name,omitempty"`
	MemberCount  int      `json:"member_count"`
	LocalPorts   []string `json:"local_ports,omitempty"`
	RemotePorts  []string `json:"remote_ports,omitempty"`
}

// buildGraph costruisce nodi e link a partire dallo stato persistito, filtrando
// per tenant consentiti (scoped==nil = tutti) e per singolo tenant (group).
func (a *App) buildGraph(scoped []string, group string) ([]*Node, []*Link, error) {
	devices, err := a.store.ListDevices()
	if err != nil {
		return nil, nil, err
	}
	versions, err := a.store.ListVersions()
	if err != nil {
		return nil, nil, err
	}
	metas, err := a.store.ListMeta()
	if err != nil {
		return nil, nil, err
	}
	topoRows, err := a.store.ListTopology()
	if err != nil {
		return nil, nil, err
	}

	inScope := func(tenant string) bool {
		if !canSeeTenant(scoped, tenant) {
			return false
		}
		if group != "" && group != "all" && tenant != group {
			return false
		}
		return true
	}

	nodesByID := map[string]*Node{}
	hostToID := map[string]string{} // hostname minuscolo -> node id (per risolvere i vicini)

	// 1. Nodi gestiti (device in inventario).
	for _, d := range devices {
		if !inScope(d.Tenant) {
			continue
		}
		status := "offline"
		version := ""
		if v, ok := versions[d.IP]; ok {
			if v.Status != "" {
				status = v.Status
			}
			version = v.Version
		} else {
			status = "offline"
		}
		label := d.Hostname
		if label == "" {
			label = d.IP
		}
		n := &Node{
			ID: d.IP, Label: label, DisplayIP: d.IP, Status: status,
			Vendor: d.Vendor, Group: d.Tenant, Version: version,
		}
		applyMeta(n, metas[d.IP])
		if n.DeviceType == "" {
			n.DeviceType = guessDeviceType(label, d.Vendor)
		}
		nodesByID[d.IP] = n
		if label != "" {
			hostToID[strings.ToLower(label)] = d.IP
		}
	}

	// 2. Arricchisci con VTP dai dati di topologia e prepara i vicini.
	type rawNeighbor struct {
		topology.Neighbor
		ownerIP string
	}
	var neighbors []rawNeighbor
	for _, row := range topoRows {
		if n, ok := nodesByID[row.IP]; ok {
			n.VTPDomain, n.VTPMode = row.VTPDomain, row.VTPMode
			if row.Hostname != "" && n.Label == n.ID {
				n.Label = row.Hostname
				hostToID[strings.ToLower(row.Hostname)] = row.IP
			}
		}
		var nbs []topology.Neighbor
		_ = json.Unmarshal([]byte(row.NeighborsJSON), &nbs)
		for _, nb := range nbs {
			neighbors = append(neighbors, rawNeighbor{Neighbor: nb, ownerIP: row.IP})
		}
	}

	// 3. Nodi scoperti (vicini CDP/LLDP non in inventario) + link.
	linkSet := map[string]*Link{}
	addLink := func(src, dst, lp, rp string) {
		if src == "" || dst == "" || src == dst {
			return
		}
		key := src + "|" + dst
		alt := dst + "|" + src
		if l, ok := linkSet[alt]; ok {
			if lp != "" {
				l.RemotePorts = appendUniq(l.RemotePorts, lp)
			}
			if rp != "" {
				l.LocalPorts = appendUniq(l.LocalPorts, rp)
			}
			return
		}
		l, ok := linkSet[key]
		if !ok {
			l = &Link{Source: src, Target: dst}
			linkSet[key] = l
		}
		if lp != "" {
			l.LocalPorts = appendUniq(l.LocalPorts, lp)
			l.LocalPort = lp
		}
		if rp != "" {
			l.RemotePorts = appendUniq(l.RemotePorts, rp)
			l.RemotePort = rp
		}
	}

	for _, rn := range neighbors {
		owner, ok := nodesByID[rn.ownerIP]
		if !ok {
			continue // owner fuori scope
		}
		// Risolvi il vicino: prima per IP gestito, poi per hostname.
		targetID := ""
		if rn.RemoteIP != "" {
			if _, ok := nodesByID[rn.RemoteIP]; ok {
				targetID = rn.RemoteIP
			}
		}
		if targetID == "" && rn.RemoteHost != "" {
			if id, ok := hostToID[strings.ToLower(rn.RemoteHost)]; ok {
				targetID = id
			}
		}
		if targetID == "" {
			// Nodo scoperto.
			discID := "discovered_" + sanitize(rn.RemoteHost)
			if rn.RemoteHost == "" {
				discID = "discovered_" + sanitize(rn.RemoteIP)
			}
			dn, exists := nodesByID[discID]
			if !exists {
				dn = &Node{
					ID: discID, Label: firstNonEmpty(rn.RemoteHost, rn.RemoteIP), DisplayIP: rn.RemoteIP,
					Status: "discovered", Vendor: "discovered", Group: owner.Group,
					Discovered: true, ReportedIP: rn.RemoteIP,
				}
				dn.DeviceType = guessDeviceType(dn.Label, "")
				nodesByID[discID] = dn
				if rn.RemoteHost != "" {
					hostToID[strings.ToLower(rn.RemoteHost)] = discID
				}
			}
			targetID = discID
		}
		addLink(owner.ID, targetID, rn.LocalPort, rn.RemotePort)
	}

	// 4. Marca i link Port-Channel usando i portchannels salvati dell'owner.
	pcByOwner := map[string][]topology.PortChannel{}
	for _, row := range topoRows {
		var pcs []topology.PortChannel
		_ = json.Unmarshal([]byte(row.PortChannelsJSON), &pcs)
		pcByOwner[row.IP] = pcs
	}
	for _, l := range linkSet {
		l.MemberCount = len(l.LocalPorts)
		if l.MemberCount == 0 {
			l.MemberCount = 1
		}
		if pcs, ok := pcByOwner[l.Source]; ok {
			for _, pc := range pcs {
				if portsOverlap(pc.Members, l.LocalPorts) {
					l.IsPortChannel = true
					l.PCName = pc.Name
					break
				}
			}
		}
		if l.MemberCount > 1 {
			l.IsPortChannel = true
		}
	}

	nodes := make([]*Node, 0, len(nodesByID))
	for _, n := range nodesByID {
		nodes = append(nodes, n)
	}
	links := make([]*Link, 0, len(linkSet))
	for _, l := range linkSet {
		links = append(links, l)
	}
	return nodes, links, nil
}

func applyMeta(n *Node, m *store.DeviceMeta) {
	if m == nil {
		return
	}
	if m.Category != "" {
		n.DeviceType = m.Category
		n.IsManual = true
	}
	if m.Subcategory != "" {
		n.Subcategory = m.Subcategory
	}
	if m.Vendor != "" {
		n.Vendor = m.Vendor
	}
	if m.Model != "" {
		n.Model = m.Model
	}
	if m.HAGroup != "" {
		n.HAGroup = m.HAGroup
	}
	if m.Name != "" {
		n.Label = m.Name
	}
	if m.Ver != "" {
		n.Version = m.Ver
	}
}

var (
	reFirewall = regexp.MustCompile(`(?i)(fw|firewall|asa|forti|palo|pan-?os|checkpoint|srx)`)
	reRouter   = regexp.MustCompile(`(?i)(rtr|router|isr|c8000|c8300|edge|gw|gateway)`)
	reWLC      = regexp.MustCompile(`(?i)(wlc|wism|controller)`)
	reAP       = regexp.MustCompile(`(?i)(^ap|-ap|air-|aironet|access-?point)`)
	reServer   = regexp.MustCompile(`(?i)(srv|server|esx|vmware|nas)`)
	rePhone    = regexp.MustCompile(`(?i)(phone|voip|sep[0-9a-f]{12})`)
	reSwitch   = regexp.MustCompile(`(?i)(sw|switch|cat|nexus|c9|c3|c2960|cbs)`)
)

// guessDeviceType euristica basata su hostname/vendor. Default: switch.
func guessDeviceType(label, vendor string) string {
	hay := label + " " + vendor
	switch {
	case reFirewall.MatchString(hay):
		return "firewall"
	case reWLC.MatchString(hay):
		return "wlc"
	case reAP.MatchString(hay):
		return "ap"
	case reServer.MatchString(hay):
		return "server"
	case rePhone.MatchString(hay):
		return "phone"
	case reRouter.MatchString(hay):
		return "router"
	case reSwitch.MatchString(hay):
		return "switch"
	default:
		return "switch"
	}
}

func sanitize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(s, "_")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func appendUniq(sl []string, v string) []string {
	for _, x := range sl {
		if x == v {
			return sl
		}
	}
	return append(sl, v)
}

func portsOverlap(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[strings.ToLower(x)] = true
	}
	for _, y := range b {
		if set[strings.ToLower(y)] {
			return true
		}
	}
	return false
}
