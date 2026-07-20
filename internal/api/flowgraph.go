package api

import (
	"crypto/sha1"
	"encoding/binary"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// graphCap limita nodi e archi restituiti dal grafo.
const graphCap = 50

// syntheticVLAN produce una VLAN deterministica dal nome del tenant, usata SOLO
// come ripiego quando non esiste un binding ARP noto per l'IP.
//
// Deve essere stabile fra riavvii e processi diversi, altrimenti lo stesso
// tenant cambierebbe colore nel grafo a ogni restart: per questo si usa sha1
// troncato e non una hash map arbitraria.
func syntheticVLAN(tenant string) int {
	sum := sha1.Sum([]byte(tenant))
	return 100 + int(binary.BigEndian.Uint16(sum[:2])%900)
}

var protoNames = map[int]string{6: "tcp", 17: "udp", 1: "icmp"}

// protoLabel replica `_PROTO_NAMES.get(p, str(p or "?"))`: protocollo assente
// o zero diventa "?".
func protoLabel(p *int) string {
	if p == nil || *p == 0 {
		return "?"
	}
	if name, ok := protoNames[*p]; ok {
		return name
	}
	return strconv.Itoa(*p)
}

type graphNode struct {
	ID       string `json:"id"`
	Bytes    int64  `json:"bytes"`
	VLAN     int    `json:"vlan"`
	VLANReal bool   `json:"vlan_real"`
}

type graphEdge struct {
	Src      string  `json:"src"`
	Dst      string  `json:"dst"`
	RateBps  float64 `json:"rate_bps"`
	Proto    string  `json:"proto"`
	Port     *int    `json:"port"`
	VLAN     int     `json:"vlan"`
	VLANReal bool    `json:"vlan_real"`

	tenant string // interno: non esposto, come nel Python
}

type protoTotal struct {
	Proto   string  `json:"proto"`
	Port    *int    `json:"port"`
	RateBps float64 `json:"rate_bps"`
}

// handleObsFlowGraph costruisce il grafo dei flussi: nodi e archi con i tassi,
// KPI di sintesi, riepilogo del tenant e ripartizione per protocollo.
//
// VLAN: se esiste un binding ARP noto per l'IP (tabella arp_entries, popolata
// dai gateway L3) si usa la VLAN reale 802.1Q; altrimenti si ricade su un
// valore sintetico e il nodo viene marcato vlan_real=false, così la UI può
// segnalarlo invece di mostrare un dato inventato in silenzio.
func (a *App) handleObsFlowGraph(w http.ResponseWriter, r *http.Request) {
	if !a.obsReady(w) {
		return
	}
	windowRaw := windowOrDefault(r.URL.Query().Get("window"), "5m")
	seconds, ok := parseWindow(windowRaw)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Invalid window: use e.g. 15m, 24h, 7d.")
		return
	}
	cutoff := time.Now().Unix() - seconds

	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)

	flows, err := a.obs.GraphFlows(cutoff, scoped, graphCap)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	spikes, err := a.obs.CountNewAnomalies(cutoff, scoped)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var edges []graphEdge
	nodeBytes := map[string]int64{}
	nodeTenant := map[string]string{}
	protoTotals := map[string]*protoTotal{}
	tenantsSeen := map[string]bool{}

	for _, f := range flows {
		rate := 0.0
		if seconds > 0 {
			rate = float64(f.TotalBytes*8) / float64(seconds)
		}
		proto := protoLabel(f.Protocol)
		tenantsSeen[f.Tenant] = true

		// I byte del nodo sommano il traffico in cui compare sia come sorgente
		// sia come destinazione: altrimenti un host solo-destinazione (un
		// server interno mai visto come src) resterebbe a 0 e verrebbe
		// scartato dal taglio ai primi 50.
		nodeBytes[f.SrcIP] += f.TotalBytes
		nodeBytes[f.DstIP] += f.TotalBytes
		if _, ok := nodeTenant[f.SrcIP]; !ok {
			nodeTenant[f.SrcIP] = f.Tenant
		}
		if _, ok := nodeTenant[f.DstIP]; !ok {
			nodeTenant[f.DstIP] = f.Tenant
		}

		edges = append(edges, graphEdge{
			Src: f.SrcIP, Dst: f.DstIP, RateBps: rate,
			Proto: proto, Port: f.DstPort, tenant: f.Tenant,
		})

		key := proto + "/" + portKey(f.DstPort)
		if pt, ok := protoTotals[key]; ok {
			pt.RateBps += rate
		} else {
			protoTotals[key] = &protoTotal{Proto: proto, Port: f.DstPort, RateBps: rate}
		}
	}

	// Primi 50 nodi per byte totali.
	topIDs := make([]string, 0, len(nodeBytes))
	for ip := range nodeBytes {
		topIDs = append(topIDs, ip)
	}
	sort.Slice(topIDs, func(i, j int) bool {
		if nodeBytes[topIDs[i]] != nodeBytes[topIDs[j]] {
			return nodeBytes[topIDs[i]] > nodeBytes[topIDs[j]]
		}
		return topIDs[i] < topIDs[j] // ordine stabile a parità di byte
	})
	if len(topIDs) > graphCap {
		topIDs = topIDs[:graphCap]
	}
	kept := make(map[string]bool, len(topIDs))
	for _, ip := range topIDs {
		kept[ip] = true
	}

	// VLAN reale dai binding ARP, vincolata al tenant di ciascun IP.
	ipTenant := make(map[string]string, len(topIDs))
	for _, ip := range topIDs {
		ipTenant[ip] = nodeTenant[ip]
	}
	realVLANs, err := a.store.VlansForIPs(ipTenant)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	type vlanInfo struct {
		vlan int
		real bool
	}
	nodeVLAN := make(map[string]vlanInfo, len(topIDs))
	for _, ip := range topIDs {
		if raw, ok := realVLANs[ip]; ok {
			if v, err := strconv.Atoi(raw); err == nil {
				nodeVLAN[ip] = vlanInfo{v, true}
				continue
			}
		}
		nodeVLAN[ip] = vlanInfo{syntheticVLAN(nodeTenant[ip]), false}
	}

	nodes := make([]graphNode, 0, len(topIDs))
	for _, ip := range topIDs {
		nodes = append(nodes, graphNode{
			ID: ip, Bytes: nodeBytes[ip],
			VLAN: nodeVLAN[ip].vlan, VLANReal: nodeVLAN[ip].real,
		})
	}

	// Restano solo gli archi fra nodi sopravvissuti al taglio.
	kterm := edges[:0]
	for _, e := range edges {
		if kept[e.Src] && kept[e.Dst] {
			kterm = append(kterm, e)
		}
	}
	edges = kterm
	sort.SliceStable(edges, func(i, j int) bool { return edges[i].RateBps > edges[j].RateBps })
	if len(edges) > graphCap {
		edges = edges[:graphCap]
	}
	for i := range edges {
		v := nodeVLAN[edges[i].Src]
		edges[i].VLAN, edges[i].VLANReal = v.vlan, v.real
	}

	throughput := 0.0
	for _, e := range edges {
		throughput += e.RateBps
	}
	topPath := map[string]any{"src": nil, "dst": nil, "pct": 0.0}
	if len(edges) > 0 {
		pct := 0.0
		if throughput > 0 {
			pct = math.Round(1000*edges[0].RateBps/throughput) / 10
		}
		topPath = map[string]any{"src": edges[0].Src, "dst": edges[0].Dst, "pct": pct}
	}
	talkerSet := map[string]bool{}
	for _, e := range edges {
		talkerSet[e.Src], talkerSet[e.Dst] = true, true
	}

	protocols := make([]protoTotal, 0, len(protoTotals))
	for _, pt := range protoTotals {
		protocols = append(protocols, *pt)
	}
	sort.SliceStable(protocols, func(i, j int) bool { return protocols[i].RateBps > protocols[j].RateBps })

	// Tenant di riferimento: il primo dello scope utente, altrimenti il primo
	// osservato nei flussi.
	tenantName := ""
	if len(scoped) > 0 {
		s := append([]string(nil), scoped...)
		sort.Strings(s)
		tenantName = s[0]
	} else if len(tenantsSeen) > 0 {
		seen := make([]string, 0, len(tenantsSeen))
		for t := range tenantsSeen {
			seen = append(seen, t)
		}
		sort.Strings(seen)
		tenantName = seen[0]
	}

	tenantEdges := edges
	if tenantName != "" {
		tenantEdges = nil
		for _, e := range edges {
			if e.tenant == tenantName {
				tenantEdges = append(tenantEdges, e)
			}
		}
	}
	var topTalker any
	if len(tenantEdges) > 0 {
		best := tenantEdges[0]
		for _, e := range tenantEdges[1:] {
			if e.RateBps > best.RateBps {
				best = e
			}
		}
		topTalker = map[string]any{"src": best.Src, "dst": best.Dst, "rate_bps": best.RateBps}
	}

	vlanSet := map[int]bool{}
	for _, ip := range topIDs {
		if tenantName == "" || nodeTenant[ip] == tenantName {
			vlanSet[nodeVLAN[ip].vlan] = true
		}
	}
	tenantVLANs := make([]int, 0, len(vlanSet))
	for v := range vlanSet {
		tenantVLANs = append(tenantVLANs, v)
	}
	if len(tenantVLANs) == 0 && tenantName != "" {
		tenantVLANs = append(tenantVLANs, syntheticVLAN(tenantName))
	}
	sort.Ints(tenantVLANs)

	writeJSON(w, http.StatusOK, map[string]any{
		"window": windowRaw,
		"nodes":  nodes,
		"edges":  edges,
		"kpi": map[string]any{
			"throughput_bps": throughput,
			"top_path":       topPath,
			"talkers":        len(talkerSet),
			"spikes":         spikes,
		},
		"tenant": map[string]any{
			"name":        nullableString(tenantName),
			"vlans":       tenantVLANs,
			"flows_shown": len(tenantEdges),
			"top_talker":  topTalker,
		},
		"protocols": protocols,
	})
}

func portKey(p *int) string {
	if p == nil {
		return ""
	}
	return strconv.Itoa(*p)
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
