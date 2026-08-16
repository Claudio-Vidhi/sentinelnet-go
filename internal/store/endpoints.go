package store

import (
	"sort"
	"strings"
	"time"
)

type EndpointInventoryOptions struct {
	Tenants   []string
	Site      string
	SwitchIP  string
	VLAN      string
	Query     string
	StaleDays int
	Limit     int
}

type EndpointItem struct {
	MAC             string   `json:"mac"`
	Tenant          string   `json:"tenant"`
	OUI             string   `json:"oui_vendor"`
	Site            string   `json:"site"`
	IPs             []string `json:"ips"`
	SwitchIP        string   `json:"switch_ip"`
	SwitchName      string   `json:"switch_name"`
	Interface       string   `json:"interface"`
	VLAN            string   `json:"vlan"`
	FirstSeen       string   `json:"first_seen"`
	LastSeen        string   `json:"last_seen"`
	SeenCount       int      `json:"seen_count"`
	AccessPortCount int      `json:"access_port_count"`
	ClientType      string   `json:"client_type"`
	Flags           []string `json:"flags"`
}

type EndpointCounts struct {
	Endpoints int `json:"endpoints"`
	Switches  int `json:"switches"`
	VLANs     int `json:"vlans"`
	Stale     int `json:"stale"`
	New       int `json:"new"`
	NoIP      int `json:"no_ip"`
	Random    int `json:"random"`
}

type EndpointInventoryResult struct {
	Results   []EndpointItem `json:"results"`
	Total     int            `json:"total"`
	Truncated bool           `json:"truncated"`
	Counts    EndpointCounts `json:"counts"`
}

type PortState struct {
	Interface string   `json:"interface"`
	State     string   `json:"state"` // "occupied", "uplink", "free"
	Physical  bool     `json:"physical"`
	UplinkTo  string   `json:"uplink_to"`
	MACs      []string `json:"macs"`
	LastSeen  string   `json:"last_seen"`
}

type PortOccupancyCounts struct {
	Total    int `json:"total"`
	Occupied int `json:"occupied"`
	Uplink   int `json:"uplink"`
	Free     int `json:"free"`
}

type PortOccupancyResult struct {
	Switch         string              `json:"switch"`
	PortListKnown  bool                `json:"port_list_known"`
	IfListAgeS     *int64              `json:"if_list_age_s"`
	Ports          []PortState         `json:"ports"`
	Counts         PortOccupancyCounts `json:"counts"`
}

// EndpointInventory restituisce l'elenco aggregato degli endpoint censiti dalla rete.
func (s *Store) EndpointInventory(opts EndpointInventoryOptions) (*EndpointInventoryResult, error) {
	if opts.StaleDays <= 0 {
		opts.StaleDays = 7
	}
	if opts.Limit <= 0 || opts.Limit > 20000 {
		opts.Limit = 2000
	}

	q := `SELECT mac, oui_vendor, vlan, switch_ip, switch_name, interface, port_channel, is_uplink, COALESCE(uplink_to,''), tenant, site, first_seen, last_seen, seen_count
	      FROM mac_sightings WHERE 1=1`
	var args []any

	if opts.Site != "" {
		q += ` AND site = ?`
		args = append(args, opts.Site)
	}
	if opts.SwitchIP != "" {
		q += ` AND switch_ip = ?`
		args = append(args, opts.SwitchIP)
	}
	if opts.VLAN != "" {
		q += ` AND vlan = ?`
		args = append(args, opts.VLAN)
	}
	if len(opts.Tenants) > 0 {
		q += ` AND tenant IN (?` + strings.Repeat(",?", len(opts.Tenants)-1) + `)`
		for _, t := range opts.Tenants {
			args = append(args, t)
		}
	}
	q += ` ORDER BY last_seen DESC`

	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type groupKey struct {
		mac    string
		tenant string
	}
	grouped := map[groupKey][]*MacSighting{}

	for rows.Next() {
		m := &MacSighting{}
		var uplink int
		if err := rows.Scan(&m.Mac, &m.OuiVendor, &m.Vlan, &m.SwitchIP, &m.SwitchName, &m.Interface,
			&m.PortChannel, &uplink, &m.UplinkTo, &m.Tenant, &m.Site, &m.FirstSeen, &m.LastSeen,
			&m.SeenCount); err != nil {
			continue
		}
		m.IsUplink = uplink != 0
		k := groupKey{mac: m.Mac, tenant: m.Tenant}
		grouped[k] = append(grouped[k], m)
	}

	// Fetch ARP IP bindings
	arpMap := map[groupKey][]string{}
	arpRows, err := s.DB.Query(`SELECT mac, ip, tenant FROM arp_entries`)
	if err == nil {
		defer arpRows.Close()
		for arpRows.Next() {
			var m, ip, t string
			if err := arpRows.Scan(&m, &ip, &t); err == nil && ip != "" {
				k := groupKey{mac: m, tenant: t}
				arpMap[k] = append(arpMap[k], ip)
			}
		}
	}

	now := time.Now()
	var results []EndpointItem
	switchesSet := map[string]bool{}
	vlansSet := map[string]bool{}
	var staleCount, newCount, noIPCount, randomCount int

	for k, list := range grouped {
		if len(list) == 0 {
			continue
		}
		best := list[0]
		firstSeen := list[0].FirstSeen
		lastSeen := list[0].LastSeen
		totalSeen := 0
		distinctPorts := map[string]bool{}

		for _, item := range list {
			totalSeen += item.SeenCount
			if item.FirstSeen < firstSeen {
				firstSeen = item.FirstSeen
			}
			if item.LastSeen > lastSeen {
				lastSeen = item.LastSeen
			}
			if !item.IsUplink && item.Interface != "" {
				distinctPorts[item.SwitchIP+":"+item.Interface] = true
			}
		}

		ips := arpMap[k]
		sort.Strings(ips)

		var flags []string
		if len(distinctPorts) > 1 {
			flags = append(flags, "AMBIGUOUS")
		}
		if len(ips) > 1 {
			flags = append(flags, "MULTI-IP")
		}
		if len(ips) == 0 {
			flags = append(flags, "NO-IP")
			noIPCount++
		}

		if tLast, err := time.Parse(time.RFC3339, lastSeen); err == nil {
			if now.Sub(tLast) > time.Duration(opts.StaleDays)*24*time.Hour {
				flags = append(flags, "STALE")
				staleCount++
			}
		}
		if tFirst, err := time.Parse(time.RFC3339, firstSeen); err == nil {
			if now.Sub(tFirst) <= time.Duration(opts.StaleDays)*24*time.Hour {
				flags = append(flags, "NEW")
				newCount++
			}
		}

		if best.SwitchIP != "" {
			switchesSet[best.SwitchIP] = true
		}
		if best.Vlan != "" {
			vlansSet[best.Vlan] = true
		}

		item := EndpointItem{
			MAC:             k.mac,
			Tenant:          k.tenant,
			OUI:             best.OuiVendor,
			Site:            best.Site,
			IPs:             ips,
			SwitchIP:        best.SwitchIP,
			SwitchName:      best.SwitchName,
			Interface:       best.Interface,
			VLAN:            best.Vlan,
			FirstSeen:       firstSeen,
			LastSeen:        lastSeen,
			SeenCount:       totalSeen,
			AccessPortCount: len(distinctPorts),
			ClientType:      "client",
			Flags:           flags,
		}

		if opts.Query != "" {
			qLower := strings.ToLower(opts.Query)
			haystack := strings.ToLower(item.MAC + " " + item.Tenant + " " + item.SwitchIP + " " + item.SwitchName + " " + strings.Join(item.IPs, " "))
			if !strings.Contains(haystack, qLower) {
				continue
			}
		}

		results = append(results, item)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].LastSeen > results[j].LastSeen
	})

	total := len(results)
	truncated := total > opts.Limit
	if truncated {
		results = results[:opts.Limit]
	}

	return &EndpointInventoryResult{
		Results:   results,
		Total:     total,
		Truncated: truncated,
		Counts: EndpointCounts{
			Endpoints: total,
			Switches:  len(switchesSet),
			VLANs:     len(vlansSet),
			Stale:     staleCount,
			New:       newCount,
			NoIP:      noIPCount,
			Random:    randomCount,
		},
	}, nil
}

// PortOccupancy calcola lo stato di occupazione per porta di uno switch.
func (s *Store) PortOccupancy(switchIP string, tenants []string) (*PortOccupancyResult, error) {
	q := `SELECT mac, tenant, switch_ip, switch_name, interface, port_channel, vlan, is_uplink, last_seen
	      FROM mac_sightings WHERE switch_ip = ?`
	var args []any
	args = append(args, switchIP)
	if len(tenants) > 0 {
		q += ` AND tenant IN (?` + strings.Repeat(",?", len(tenants)-1) + `)`
		for _, t := range tenants {
			args = append(args, t)
		}
	}

	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byPort := map[string][]*MacSighting{}
	for rows.Next() {
		m := &MacSighting{}
		var uplink int
		if err := rows.Scan(&m.Mac, &m.Tenant, &m.SwitchIP, &m.SwitchName, &m.Interface,
			&m.PortChannel, &m.Vlan, &uplink, &m.LastSeen); err == nil {
			m.IsUplink = uplink != 0
			ifaceKey := strings.ToLower(m.Interface)
			byPort[ifaceKey] = append(byPort[ifaceKey], m)
		}
	}

	var ports []PortState
	var occCount, uplinkCount, freeCount int

	for iface, sightings := range byPort {
		var macs []string
		isUplink := false
		lastSeen := ""
		for _, st := range sightings {
			if st.IsUplink {
				isUplink = true
			}
			macs = append(macs, st.Mac)
			if st.LastSeen > lastSeen {
				lastSeen = st.LastSeen
			}
		}

		state := "free"
		if isUplink {
			state = "uplink"
			uplinkCount++
		} else if len(macs) > 0 {
			state = "occupied"
			occCount++
		} else {
			freeCount++
		}

		sort.Strings(macs)

		ports = append(ports, PortState{
			Interface: iface,
			State:     state,
			Physical:  true,
			MACs:      macs,
			LastSeen:  lastSeen,
		})
	}

	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Interface < ports[j].Interface
	})

	return &PortOccupancyResult{
		Switch:        switchIP,
		PortListKnown: len(ports) > 0,
		Ports:         ports,
		Counts: PortOccupancyCounts{
			Total:    len(ports),
			Occupied: occCount,
			Uplink:   uplinkCount,
			Free:     freeCount,
		},
	}, nil
}
