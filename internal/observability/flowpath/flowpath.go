// Package flowpath: tracciamento del percorso logico del traffico per un incidente.
// Porta di observability/flowpath.py.
package flowpath

import (
	"fmt"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/endpoints"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

type Hop struct {
	Kind       string             `json:"kind"`
	Known      bool               `json:"known"`
	IP         string             `json:"ip,omitempty"`
	MAC        string             `json:"mac,omitempty"`
	MACInfo    *endpoints.MACInfo `json:"mac_info,omitempty"`
	Label      string             `json:"label"`
	Switch     string             `json:"switch,omitempty"`
	SwitchIP   string             `json:"switch_ip,omitempty"`
	Port       string             `json:"port,omitempty"`
	VLAN       string             `json:"vlan,omitempty"`
	Device     string             `json:"device,omitempty"`
	DeviceIP   string             `json:"device_ip,omitempty"`
	DeviceType string             `json:"device_type,omitempty"`
}

type Result struct {
	Direction string `json:"direction"`
	Hops      []Hop  `json:"hops"`
	Complete  bool   `json:"complete"`
}

type ClientLookup interface {
	ClientMap(mac, ip, sourceIP string, tenants []string, limit int) ([]*store.ClientMapRow, error)
}

func client(st ClientLookup, ip, tenant string) *store.ClientMapRow {
	if st == nil || ip == "" {
		return nil
	}
	var tenants []string
	if tenant != "" {
		tenants = []string{tenant}
	}
	entries, err := st.ClientMap("", ip, "", tenants, 1)
	if err != nil || len(entries) == 0 {
		return nil
	}
	return entries[0]
}

func endpointHop(ip string, c *store.ClientMapRow) Hop {
	mac := ""
	if c != nil && c.ARPEntry != nil {
		mac = c.MAC
	}
	return Hop{
		Kind:    "endpoint",
		Known:   true,
		IP:      ip,
		MAC:     mac,
		MACInfo: endpoints.ClassifyMAC(mac),
		Label:   endpoints.Describe(ip),
	}
}

func accessHop(c *store.ClientMapRow) Hop {
	if c == nil || c.SwitchPort == "" {
		return Hop{
			Kind:  "access",
			Known: false,
			Label: "porta di accesso sconosciuta (manca una MAC scan)",
		}
	}
	sw := c.SwitchName
	if sw == "" {
		sw = c.SwitchIP
	}
	label := fmt.Sprintf("%s:%s", sw, c.SwitchPort)
	if c.PortVLAN != "" {
		label += fmt.Sprintf(" (VLAN %s)", c.PortVLAN)
	}
	return Hop{
		Kind:     "access",
		Known:    true,
		Switch:   sw,
		SwitchIP: c.SwitchIP,
		Port:     c.SwitchPort,
		VLAN:     c.PortVLAN,
		Label:    label,
	}
}

func gatewayHop(c *store.ClientMapRow) *Hop {
	if c == nil || c.ARPEntry == nil || c.SourceIP == "" {
		return nil
	}
	name := c.SourceName
	if name == "" {
		name = c.SourceIP
	}
	kind := c.SourceType
	if kind == "" {
		kind = "gateway"
	}
	return &Hop{
		Kind:       "gateway",
		Known:      true,
		Device:     name,
		DeviceIP:   c.SourceIP,
		DeviceType: kind,
		Label:      fmt.Sprintf("%s (%s)", name, kind),
	}
}

// Build costruisce il percorso logico del traffico fra srcIP e dstIP.
func Build(st ClientLookup, srcIP, dstIP, tenant, dstTenant string) Result {
	dir := endpoints.TrafficDirection(srcIP, dstIP)
	if dir == "" || srcIP == "" || dstIP == "" {
		return Result{Direction: dir, Hops: []Hop{}, Complete: false}
	}

	srcClient := client(st, srcIP, tenant)
	hops := []Hop{
		endpointHop(srcIP, srcClient),
		accessHop(srcClient),
	}

	gw := gatewayHop(srcClient)
	if gw != nil {
		hops = append(hops, *gw)
	}

	if dstTenant == "" {
		dstTenant = tenant
	}

	if dir == "east_west" {
		dstClient := client(st, dstIP, dstTenant)
		dstGW := gatewayHop(dstClient)
		if dstGW != nil && (gw == nil || dstGW.DeviceIP != gw.DeviceIP) {
			hops = append(hops, *dstGW)
		}
		hops = append(hops, accessHop(dstClient))
		hops = append(hops, endpointHop(dstIP, dstClient))
	} else if dir == "north_south" {
		hops = append(hops, Hop{
			Kind:  "perimeter",
			Known: true,
			Label: fmt.Sprintf("perimetro -> %s", endpoints.Describe(dstIP)),
		})
	} else {
		hops = append(hops, Hop{
			Kind:  "destination",
			Known: true,
			Label: endpoints.Describe(dstIP),
		})
	}

	complete := true
	for _, h := range hops {
		if !h.Known {
			complete = false
			break
		}
	}

	return Result{
		Direction: dir,
		Hops:      hops,
		Complete:  complete,
	}
}
