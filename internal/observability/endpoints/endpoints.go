// Package endpoints: classificazione e descrizione di indirizzi IP e MAC.
// Porta di observability/endpoints.py.
package endpoints

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

type EndpointInfo struct {
	Address  string `json:"address"`
	Family   string `json:"family"`
	Category string `json:"category"`
	Role     string `json:"role,omitempty"`
	Scope    string `json:"scope"`
	Label    string `json:"label,omitempty"`
}

type MACInfo struct {
	MAC            string `json:"mac"`
	OUI            string `json:"oui"`
	Category       string `json:"category"`
	Administration string `json:"administration"`
	VendorKind     string `json:"vendor_kind,omitempty"`
	Label          string `json:"label,omitempty"`
}

var wellKnown = map[string][2]string{
	"0.0.0.0":         {"unspecified", "Indirizzo non specificato"},
	"255.255.255.255": {"broadcast_limited", "Broadcast limitato"},
	"224.0.0.1":       {"all_hosts", "All Hosts"},
	"224.0.0.2":       {"all_routers", "All Routers"},
	"224.0.0.4":       {"dvmrp", "DVMRP Routers"},
	"224.0.0.5":       {"ospf_allspfrouters", "OSPF AllSPFRouters"},
	"224.0.0.6":       {"ospf_alldrouters", "OSPF AllDRouters"},
	"224.0.0.9":       {"rip2", "RIPv2 Routers"},
	"224.0.0.10":      {"eigrp", "EIGRP Routers"},
	"224.0.0.13":      {"pim", "PIM Routers"},
	"224.0.0.18":      {"vrrp", "VRRP"},
	"224.0.0.22":      {"igmpv3", "IGMPv3 Reports"},
	"224.0.0.102":     {"hsrpv2_glbp", "HSRPv2 / GLBP"},
	"224.0.0.251":     {"mdns", "mDNS"},
	"224.0.0.252":     {"llmnr", "LLMNR"},
	"224.0.1.1":       {"ntp", "NTP Multicast"},
	"224.0.1.39":      {"cisco_rp_announce", "Cisco RP Announce"},
	"224.0.1.40":      {"cisco_rp_discovery", "Cisco RP Discovery"},
	"239.255.255.250": {"ssdp", "SSDP / UPnP"},
}

type specialNet struct {
	prefix   netip.Prefix
	category string
	scope    string
}

var specialNetworks []specialNet
var linkLocalMCast netip.Prefix

func init() {
	specs := []struct {
		cidr, category, scope string
	}{
		{"100.64.0.0/10", "cgnat", "site"},
		{"192.0.2.0/24", "documentation", "global"},
		{"198.51.100.0/24", "documentation", "global"},
		{"203.0.113.0/24", "documentation", "global"},
		{"198.18.0.0/15", "benchmark", "global"},
		{"192.88.99.0/24", "6to4_relay", "global"},
		{"240.0.0.0/4", "reserved", "global"},
	}
	for _, s := range specs {
		if p, err := netip.ParsePrefix(s.cidr); err == nil {
			specialNetworks = append(specialNetworks, specialNet{prefix: p, category: s.category, scope: s.scope})
		}
	}
	linkLocalMCast, _ = netip.ParsePrefix("224.0.0.0/24")
}

var (
	cacheMu     sync.RWMutex
	ipCache     = make(map[string]*EndpointInfo)
	macCache    = make(map[string]*MACInfo)
	virtualOUIs = map[string]string{
		"00:50:56": "VMware",
		"00:0c:29": "VMware",
		"00:05:69": "VMware",
		"00:1c:14": "VMware",
		"00:15:5d": "Hyper-V",
		"00:03:ff": "Hyper-V",
		"08:00:27": "VirtualBox",
		"0a:00:27": "VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:16:3e": "Xen",
		"00:1c:42": "Parallels",
	}
)

// Classify classifica un indirizzo IP in metadati strutturati.
func Classify(address string) *EndpointInfo {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}

	cacheMu.RLock()
	if info, ok := ipCache[address]; ok {
		cacheMu.RUnlock()
		return info
	}
	cacheMu.RUnlock()

	ip, err := netip.ParseAddr(address)
	if err != nil {
		return nil
	}

	var role, label string
	if wk, ok := wellKnown[ip.String()]; ok {
		role, label = wk[0], wk[1]
	}

	var category, scope string
	if ip.IsUnspecified() {
		category, scope = "unspecified", "host"
	} else if ip.IsLoopback() {
		category, scope = "loopback", "host"
	} else if ip.IsLinkLocalUnicast() {
		category, scope = "link_local", "link-local"
	} else if ip.String() == "255.255.255.255" {
		category, scope = "broadcast", "link-local"
	} else if ip.IsMulticast() {
		category = "multicast"
		if linkLocalMCast.Contains(ip) {
			scope = "link-local"
		} else {
			scope = "global"
		}
	} else {
		matchedSpecial := false
		for _, sn := range specialNetworks {
			if sn.prefix.Contains(ip) {
				category, scope = sn.category, sn.scope
				matchedSpecial = true
				break
			}
		}
		if !matchedSpecial {
			if ip.IsPrivate() {
				category, scope = "private", "site"
			} else {
				category, scope = "public", "global"
			}
		}
	}

	info := &EndpointInfo{
		Address:  ip.String(),
		Family:   fmt.Sprintf("ipv%d", ip.BitLen()/32*4),
		Category: category,
		Role:     role,
		Scope:    scope,
		Label:    label,
	}

	cacheMu.Lock()
	if len(ipCache) < 4096 {
		ipCache[address] = info
	}
	cacheMu.Unlock()

	return info
}

// Describe ritorna un'etichetta leggibile o l'IP.
func Describe(address string) string {
	info := Classify(address)
	if info != nil && info.Label != "" {
		return fmt.Sprintf("%s (%s)", info.Label, info.Address)
	}
	if address == "" {
		return "?"
	}
	return address
}

// IsEndpoint ritorna true se l'indirizzo appartiene a un host reale.
func IsEndpoint(address string) bool {
	info := Classify(address)
	if info == nil {
		return false
	}
	switch info.Category {
	case "multicast", "broadcast", "loopback", "unspecified", "reserved":
		return false
	default:
		return true
	}
}

// TrafficDirection deduce east_west, north_south, control_plane, local.
func TrafficDirection(src, dst string) string {
	sInfo, dInfo := Classify(src), Classify(dst)
	if sInfo == nil || dInfo == nil {
		return ""
	}
	if dInfo.Category == "multicast" || dInfo.Category == "broadcast" {
		return "control_plane"
	}
	if !IsEndpoint(src) || !IsEndpoint(dst) {
		return "local"
	}
	isInternal := func(cat string) bool {
		return cat == "private" || cat == "cgnat" || cat == "link_local"
	}
	if isInternal(sInfo.Category) && isInternal(dInfo.Category) {
		return "east_west"
	}
	return "north_south"
}

func normalizeMAC(mac string) string {
	if mac == "" {
		return ""
	}
	var sb strings.Builder
	for _, r := range strings.ToLower(mac) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			sb.WriteRune(r)
		}
	}
	h := sb.String()
	if len(h) != 12 {
		return ""
	}
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s", h[0:2], h[2:4], h[4:6], h[6:8], h[8:10], h[10:12])
}

// ClassifyMAC analizza un indirizzo MAC.
func ClassifyMAC(mac string) *MACInfo {
	norm := normalizeMAC(mac)
	if norm == "" {
		return nil
	}

	cacheMu.RLock()
	if info, ok := macCache[norm]; ok {
		cacheMu.RUnlock()
		return info
	}
	cacheMu.RUnlock()

	hw, err := net.ParseMAC(norm)
	if err != nil || len(hw) < 6 {
		return nil
	}

	first := hw[0]
	oui := norm[:8]
	local := (first & 0b10) != 0

	var category string
	if norm == "ff:ff:ff:ff:ff:ff" {
		category = "broadcast"
	} else if (first & 0b1) != 0 {
		category = "multicast"
	} else {
		category = "unicast"
	}

	vendorKind := virtualOUIs[oui]
	var label string
	if vendorKind != "" {
		label = fmt.Sprintf("macchina virtuale %s", vendorKind)
	} else if category == "broadcast" {
		label = "Broadcast"
	} else if category == "multicast" {
		label = "Multicast L2"
	} else if local {
		label = "indirizzo amministrato localmente (VM o MAC randomizzato)"
	}

	admin := "universale"
	if local {
		admin = "locale"
	}

	info := &MACInfo{
		MAC:            norm,
		OUI:            oui,
		Category:       category,
		Administration: admin,
		VendorKind:     vendorKind,
		Label:          label,
	}

	cacheMu.Lock()
	if len(macCache) < 4096 {
		macCache[norm] = info
	}
	cacheMu.Unlock()

	return info
}

// DescribeMAC ritorna etichetta leggibile del MAC.
func DescribeMAC(mac string) string {
	info := ClassifyMAC(mac)
	if info == nil {
		if mac == "" {
			return "?"
		}
		return mac
	}
	if info.Label != "" {
		return fmt.Sprintf("%s (%s)", info.MAC, info.Label)
	}
	return info.MAC
}

// IsStableIdentity verifica se il MAC pu valere come identit persistente.
func IsStableIdentity(mac string) bool {
	info := ClassifyMAC(mac)
	if info == nil || info.Category != "unicast" {
		return false
	}
	return info.Administration == "universale" || info.VendorKind != ""
}
