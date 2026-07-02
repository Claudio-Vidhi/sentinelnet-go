// Package topology: estrae vicini CDP/LLDP, port-channel e VTP dalle config di backup.
package topology

import (
	"regexp"
	"strings"
)

type Neighbor struct {
	LocalHost  string
	LocalPort  string
	RemoteHost string
	RemotePort string
	RemoteIP   string
}

type PortChannel struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

type DeviceTopology struct {
	Hostname     string
	VTPDomain    string
	VTPMode      string
	PortChannels []PortChannel
	Neighbors    []Neighbor
}

var (
	reHostname   = regexp.MustCompile(`(?m)^hostname\s+(\S+)`)
	reVTPDomain  = regexp.MustCompile(`(?im)^\s*VTP Domain Name\s*:\s*(\S+)`)
	reVTPMode    = regexp.MustCompile(`(?im)^\s*VTP Operating Mode\s*:\s*(\S+)`)
	reVTPDomCfg  = regexp.MustCompile(`(?im)^vtp domain\s+(\S+)`)
	reVTPModeCfg = regexp.MustCompile(`(?im)^vtp mode\s+(\S+)`)
)

// ParseConfig estrae hostname, VTP e port-channel dalla running-config.
func ParseConfig(cfg string) DeviceTopology {
	dt := DeviceTopology{}
	if m := reHostname.FindStringSubmatch(cfg); len(m) == 2 {
		dt.Hostname = m[1]
	}
	if m := reVTPDomain.FindStringSubmatch(cfg); len(m) == 2 {
		dt.VTPDomain = m[1]
	} else if m := reVTPDomCfg.FindStringSubmatch(cfg); len(m) == 2 {
		dt.VTPDomain = m[1]
	}
	if m := reVTPMode.FindStringSubmatch(cfg); len(m) == 2 {
		dt.VTPMode = strings.ToLower(m[1])
	} else if m := reVTPModeCfg.FindStringSubmatch(cfg); len(m) == 2 {
		dt.VTPMode = strings.ToLower(m[1])
	}
	dt.PortChannels = parsePortChannels(cfg)
	return dt
}

// parsePortChannels: legge "channel-group N" sotto le interfacce fisiche e
// aggrega le interfacce membro per Port-channel.
func parsePortChannels(cfg string) []PortChannel {
	lines := strings.Split(cfg, "\n")
	members := map[string][]string{} // "Port-channelN" -> [interfaces]
	var curIface string
	reIface := regexp.MustCompile(`(?i)^interface\s+(\S+)`)
	reChan := regexp.MustCompile(`(?i)channel-group\s+(\d+)`)
	for _, l := range lines {
		if m := reIface.FindStringSubmatch(l); len(m) == 2 {
			curIface = m[1]
			continue
		}
		if strings.HasPrefix(l, "interface") {
			curIface = ""
		}
		if m := reChan.FindStringSubmatch(l); len(m) == 2 && curIface != "" {
			po := "Port-channel" + m[1]
			members[po] = append(members[po], curIface)
		}
	}
	var out []PortChannel
	for name, ifs := range members {
		out = append(out, PortChannel{Name: name, Members: ifs})
	}
	return out
}

var (
	// CDP: "Device ID: SW2.example.com" ... "Interface: Gi0/1, Port ID (outgoing port): Gi0/2"
	reCDPDevice = regexp.MustCompile(`(?i)Device ID:\s*(\S+)`)
	reCDPPorts  = regexp.MustCompile(`(?i)Interface:\s*([\w./\-]+),\s*Port ID \(outgoing port\):\s*([\w./\-]+)`)
	reCDPIP     = regexp.MustCompile(`(?i)IP(?:v4)? address:\s*([\d.]+)`)
)

// ParseCDPNeighbors estrae i vicini dall'output "show cdp neighbors detail".
func ParseCDPNeighbors(localHost, out string) []Neighbor {
	var neighbors []Neighbor
	blocks := regexp.MustCompile(`(?m)^-{5,}`).Split(out, -1)
	for _, b := range blocks {
		dev := reCDPDevice.FindStringSubmatch(b)
		if len(dev) != 2 {
			continue
		}
		n := Neighbor{LocalHost: localHost, RemoteHost: shortHost(dev[1])}
		if p := reCDPPorts.FindStringSubmatch(b); len(p) == 3 {
			n.LocalPort = p[1]
			n.RemotePort = p[2]
		}
		if ip := reCDPIP.FindStringSubmatch(b); len(ip) == 2 {
			n.RemoteIP = ip[1]
		}
		neighbors = append(neighbors, n)
	}
	return neighbors
}

// ParseLLDPNeighbors estrae i vicini da "show lldp neighbors detail".
func ParseLLDPNeighbors(localHost, out string) []Neighbor {
	var neighbors []Neighbor
	reLocal := regexp.MustCompile(`(?i)Local (?:Intf|Port id):\s*([\w./\-]+)`)
	reSys := regexp.MustCompile(`(?i)System Name:\s*(\S+)`)
	rePort := regexp.MustCompile(`(?im)^Port id:\s*([\w./\-]+)`)
	reMgmt := regexp.MustCompile(`(?i)Management Address(?:es)?:?\s*\n?\s*(?:IP:\s*)?([\d.]+)`)
	// Blocchi separati SOLO dalle righe di trattini: dividere anche su
	// "Local Intf" mangerebbe proprio la riga da cui estrarre la porta locale.
	blocks := regexp.MustCompile(`(?m)^-{4,}\s*$`).Split(out, -1)
	for _, b := range blocks {
		sys := reSys.FindStringSubmatch(b)
		if len(sys) != 2 {
			continue
		}
		n := Neighbor{LocalHost: localHost, RemoteHost: shortHost(sys[1])}
		if m := reLocal.FindStringSubmatch(b); len(m) == 2 {
			n.LocalPort = m[1]
		}
		if m := rePort.FindStringSubmatch(b); len(m) == 2 {
			n.RemotePort = m[1]
		}
		if m := reMgmt.FindStringSubmatch(b); len(m) == 2 {
			n.RemoteIP = m[1]
		}
		neighbors = append(neighbors, n)
	}
	return neighbors
}

func shortHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	if i := strings.IndexByte(h, '('); i > 0 {
		return strings.TrimSpace(h[:i])
	}
	return h
}
