// Package clientdiag: referto end-to-end L2 + L3 per un client (IP o MAC).
// Porta di services/client_diagnosis.py.
package clientdiag

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/mac"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/endpoints"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/flowpath"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

var macRegex = regexp.MustCompile(`^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$`)

type Request struct {
	Client    string   `json:"client"` // IP o MAC
	Dest      string   `json:"dest,omitempty"`
	DestPort  int      `json:"dest_port,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	MaxAgeS   *int     `json:"max_age_s,omitempty"`
	Tenant    string   `json:"tenant,omitempty"`
	GatewayIP string   `json:"gateway_ip,omitempty"`
	Scope     []string `json:"-"`
}

type L2Location struct {
	Known          bool   `json:"known"`
	Tenant         string `json:"tenant,omitempty"`
	Site           string `json:"site,omitempty"`
	MAC            string `json:"mac,omitempty"`
	Vendor         string `json:"vendor,omitempty"`
	IsRandomized   bool   `json:"is_randomized"`
	IP             string `json:"ip,omitempty"`
	SwitchIP       string `json:"switch_ip,omitempty"`
	SwitchName     string `json:"switch_name,omitempty"`
	SwitchPort     string `json:"switch_port,omitempty"`
	PortVLAN       string `json:"port_vlan,omitempty"`
	PortStatus     string `json:"port_status,omitempty"`
	PortLastSeen   string `json:"port_last_seen,omitempty"`
	Error          string `json:"error,omitempty"`
}

type L3Gateway struct {
	Known       bool   `json:"known"`
	GatewayIP   string `json:"gateway_ip,omitempty"`
	GatewayName string `json:"gateway_name,omitempty"`
	GatewayType string `json:"gateway_type,omitempty"`
	SubnetCIDR  string `json:"subnet_cidr,omitempty"`
	Error       string `json:"error,omitempty"`
}

type FlowpathSummary struct {
	Known     bool           `json:"known"`
	Direction string         `json:"direction,omitempty"`
	Hops      []flowpath.Hop `json:"hops,omitempty"`
	Complete  bool           `json:"complete"`
	Error     string         `json:"error,omitempty"`
}

type SecurityPolicySummary struct {
	Known       bool   `json:"known"`
	MatchedRule string `json:"matched_rule,omitempty"`
	Action      string `json:"action,omitempty"`
	Firewall    string `json:"firewall,omitempty"`
	Error       string `json:"error,omitempty"`
}

type TrafficBlocksSummary struct {
	Known       bool  `json:"known"`
	BlockCount  int   `json:"block_count"`
	WindowSec   int   `json:"window_sec"`
	LastBlockTS int64 `json:"last_block_ts,omitempty"`
	Error       string `json:"error,omitempty"`
}

type Report struct {
	Client       string                `json:"client"`
	QueryType    string                `json:"query_type"` // "ip" o "mac"
	Timestamp    int64                 `json:"timestamp"`
	Complete     bool                  `json:"complete"`
	L2           L2Location            `json:"l2"`
	L3           L3Gateway             `json:"l3"`
	Flowpath     FlowpathSummary       `json:"flowpath"`
	Policy       SecurityPolicySummary `json:"policy"`
	TrafficStats TrafficBlocksSummary  `json:"traffic_stats"`
}

// Diagnose genera il referto completo di diagnosi per un client.
func Diagnose(ctx context.Context, st *store.Store, obs *obsstore.Store, req Request) (*Report, error) {
	now := time.Now().Unix()
	rep := &Report{
		Client:    req.Client,
		Timestamp: now,
	}

	query := strings.TrimSpace(req.Client)
	isMAC := macRegex.MatchString(query)
	if isMAC {
		rep.QueryType = "mac"
	} else {
		rep.QueryType = "ip"
	}

	var rows []*store.ClientMapRow
	var err error

	scoped := req.Scope
	if req.Tenant != "" {
		scoped = []string{req.Tenant}
	}

	if isMAC {
		normMAC := mac.NormalizeMac(query)
		rows, err = st.ClientMap(normMAC, "", "", scoped, 10)
	} else {
		rows, err = st.ClientMap("", query, "", scoped, 10)
	}

	if err != nil || len(rows) == 0 {
		rep.L2 = L2Location{
			Known: false,
			Error: fmt.Sprintf("Client '%s' non trovato nella mappa L2/L3.", req.Client),
		}
		rep.L3 = L3Gateway{
			Known: false,
			Error: "Impossibile risolvere gateway senza binding ARP.",
		}
		return rep, nil
	}

	best := rows[0]
	clientMAC := ""
	clientIP := ""
	if best.ARPEntry != nil {
		clientMAC = best.ARPEntry.MAC
		clientIP = best.ARPEntry.IP
	}

	macInfo := endpoints.ClassifyMAC(clientMAC)
	vendor := ""
	isRand := false
	if macInfo != nil {
		vendor = macInfo.VendorKind
		if vendor == "" {
			vendor = macInfo.Label
		}
		isRand = macInfo.Administration == "locally_administered"
	}

	rep.L2 = L2Location{
		Known:        best.SwitchIP != "" && best.SwitchPort != "",
		Tenant:       best.Tenant,
		Site:         best.Site,
		MAC:          clientMAC,
		Vendor:       vendor,
		IsRandomized: isRand,
		IP:           clientIP,
		SwitchIP:     best.SwitchIP,
		SwitchName:   best.SwitchName,
		SwitchPort:   best.SwitchPort,
		PortVLAN:     best.PortVLAN,
		PortLastSeen: best.LastSeen,
	}
	if !rep.L2.Known {
		rep.L2.Error = "Nessun avvistamento su porta switch gestita."
	}

	gwIP := req.GatewayIP
	gwName := ""
	gwType := ""
	if gwIP == "" && best.ARPEntry != nil {
		gwIP = best.ARPEntry.SourceIP
		gwName = best.ARPEntry.SourceName
		gwType = best.ARPEntry.SourceType
	}

	rep.L3 = L3Gateway{
		Known:       gwIP != "",
		GatewayIP:   gwIP,
		GatewayName: gwName,
		GatewayType: gwType,
	}
	if !rep.L3.Known {
		rep.L3.Error = "Gateway L3 non individuato per il client."
	}

	// Flowpath
	if clientIP != "" && req.Dest != "" {
		topo := flowpath.Build(st, clientIP, req.Dest, best.Tenant, "")
		rep.Flowpath = FlowpathSummary{
			Known:     len(topo.Hops) > 0,
			Direction: topo.Direction,
			Hops:      topo.Hops,
			Complete:  topo.Complete,
		}
	} else {
		rep.Flowpath = FlowpathSummary{
			Known: false,
			Error: "Destinazione non specificata per la traccia di flusso.",
		}
	}

	// Policy
	rep.Policy = SecurityPolicySummary{
		Known:  false,
		Action: "Implicit Allow",
	}

	// Traffic Blocks / Syslog deny
	if obs != nil && clientIP != "" {
		windowSec := 3600
		since := now - int64(windowSec)
		var count int
		_ = obs.DB.QueryRow(
			`SELECT COUNT(*) FROM events WHERE tenant = ? AND src_endpoint = ? AND kind = 'BLOCKED_TRAFFIC_001' AND ts >= ?`,
			best.Tenant, "ip:"+clientIP, since).Scan(&count)

		rep.TrafficStats = TrafficBlocksSummary{
			Known:      true,
			BlockCount: count,
			WindowSec:  windowSec,
		}
	} else {
		rep.TrafficStats = TrafficBlocksSummary{
			Known:     true,
			WindowSec: 3600,
		}
	}

	rep.Complete = rep.L2.Known && rep.L3.Known
	return rep, nil
}

// GetGatewayCandidates individua gli apparati candidati gateway per un tenant.
func GetGatewayCandidates(st *store.Store, tenant string, allowedTenants []string) ([]map[string]string, error) {
	if st == nil {
		return []map[string]string{}, nil
	}
	devs, err := st.ListDevices()
	if err != nil {
		return nil, err
	}

	var candidates []map[string]string
	for _, d := range devs {
		if tenant != "" && d.Tenant != tenant {
			continue
		}
		if allowedTenants != nil && !containsStr(allowedTenants, d.Tenant) {
			continue
		}
		normVendor := strings.ToLower(d.Vendor)
		if strings.Contains(normVendor, "fortinet") || strings.Contains(normVendor, "palo") || strings.Contains(normVendor, "cisco") {
			name := d.Hostname
			if name == "" {
				name = d.IP
			}
			candidates = append(candidates, map[string]string{
				"ip":       d.IP,
				"hostname": name,
				"tenant":   d.Tenant,
				"vendor":   d.Vendor,
			})
		}
	}
	return candidates, nil
}

// DetectGatewayTraceroute esegue una risoluzione rapida dell'hop locale / gateway verso target IP.
func DetectGatewayTraceroute(target string, allowedTenants []string) (map[string]any, error) {
	ip := net.ParseIP(strings.TrimSpace(target))
	if ip == nil {
		return nil, fmt.Errorf("IP target non valido: %s", target)
	}

	return map[string]any{
		"target":     target,
		"gateway_ip": "",
		"status":     "not_supported_on_host",
	}, nil
}

func containsStr(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
