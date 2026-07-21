package mcp

import "strconv"

func strP() map[string]any { return map[string]any{"type": "string"} }

func intP() map[string]any { return map[string]any{"type": "integer"} }

func boolP() map[string]any { return map[string]any{"type": "boolean"} }

func objP(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// mergeDesc aggiunge/description a uno schema base (porta di {**_S, "description":...}).
func mergeDesc(base map[string]any, desc string) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	out["description"] = desc
	return out
}

// nonEmpty copia in query solo le chiavi con valore stringa non vuoto (porta
// del `{k: v for k, v in a.items() if v}` del Python).
func nonEmpty(a map[string]any, keys ...string) map[string]string {
	q := map[string]string{}
	for _, k := range keys {
		if s, _ := a[k].(string); s != "" {
			q[k] = s
		}
	}
	if len(q) == 0 {
		return nil
	}
	return q
}

// present copia nel body solo le chiavi presenti (porta del `if a.get(k) is not
// None`). Preserva il tipo (string/number/bool) dell'argomento.
func present(a map[string]any, keys ...string) any {
	b := map[string]any{}
	for _, k := range keys {
		if v, ok := a[k]; ok && v != nil {
			b[k] = v
		}
	}
	if len(b) == 0 {
		return nil
	}
	return b
}

func str(a map[string]any, k string) string { s, _ := a[k].(string); return s }

func strOr(a map[string]any, k, def string) string {
	if s, ok := a[k].(string); ok && s != "" {
		return s
	}
	return def
}

// intOr legge un intero (accetta float64 da JSON o int nativo) con default.
func intOr(a map[string]any, k string, def int) int {
	v, ok := a[k]
	if !ok || v == nil {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return def
	}
}

// Tools è il registro dei tool MCP, nell'ordine del TOOLS dict del Python.
var Tools = []Tool{
	{
		Name:        "list_devices",
		Description: "List all managed network devices (IP, hostname, vendor, group/site, status) from the SentinelNet inventory.",
		InputSchema: objP(map[string]any{}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/local-devices"}
		},
	},
	{
		Name:        "get_network_map",
		Description: "Get the discovered network topology: nodes (devices with type, vendor, VTP info) and links (local/remote ports, Port-Channel/LAG membership with per-side aggregate ids).",
		InputSchema: objP(map[string]any{"group": mergeDesc(strP(), "Site/group filter, 'all' for everything")}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/network-map",
				Query: map[string]string{"group": strOr(a, "group", "all")}}
		},
	},
	{
		Name:        "get_port_channels",
		Description: "List all EtherChannel/Port-Channel aggregates detected in the network with their member interfaces per device.",
		InputSchema: objP(map[string]any{}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/portchannels"}
		},
	},
	{
		Name:        "locate_mac",
		Description: "Locate a MAC address in the network: returns the access switch/port where the host is attached (uplink/trunk sightings filtered out).",
		InputSchema: objP(map[string]any{"mac": mergeDesc(strP(), "MAC address, any format")}, "mac"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/mac/locate", Query: map[string]string{"mac": str(a, "mac")}}
		},
	},
	{
		Name:        "search_mac",
		Description: "Search the historical MAC address table across all switches. All filters optional.",
		InputSchema: objP(map[string]any{"mac": strP(), "vlan": strP(), "interface": strP(),
			"switch": mergeDesc(strP(), "Switch IP")}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/mac/search", Query: nonEmpty(a, "mac", "vlan", "interface", "switch")}
		},
	},
	{
		Name:        "mac_to_ip",
		Description: "Resolve MAC <-> IP bindings for network clients, collected from the ARP tables of the L3 gateways (L3 switches or firewalls, whichever routes the VLAN). Search by MAC (full or fragment) or IP prefix.",
		InputSchema: objP(map[string]any{"mac": mergeDesc(strP(), "MAC address or fragment"),
			"ip": mergeDesc(strP(), "IP address or prefix")}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/arp/search", Query: nonEmpty(a, "mac", "ip")}
		},
	},
	{
		Name:        "client_map",
		Description: "Unified client view: MAC + current IP (from the routing gateway's ARP) + access switch/port (from the MAC table). Answers 'who is 10.0.0.5 and which port is it attached to'.",
		InputSchema: objP(map[string]any{"mac": strP(), "ip": strP()}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/arp/client-map", Query: nonEmpty(a, "mac", "ip")}
		},
	},
	{
		Name:        "arp_scan",
		Description: "Collect the ARP tables from managed L3 devices (switches and firewalls) and store MAC<->IP bindings in the historical DB. Requires operator role; optionally restrict to one device IP or a site/group.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "Only this device (optional)"),
			"group": mergeDesc(strP(), "Site/group filter, 'all' default")}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/arp/scan",
				Body: map[string]any{"ip": a["ip"], "group": strOr(a, "group", "all")}}
		},
	},
	{
		Name:        "analyze_config",
		Description: "Analyze the stored configuration backup of a device: VLANs, SVIs, routing, trunk/access ports, neighbors, security findings.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "Device IP")}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/config-analyzer/" + str(a, "ip")}
		},
	},
	{
		Name:        "get_triage_status",
		Description: "Get the status of the last triage run (reachability, backup, version detection) for every device.",
		InputSchema: objP(map[string]any{}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/triage-status"}
		},
	},
	{
		Name:        "send_cli_command",
		Description: "Run a single CLI command on a managed device via SSH and return the output. Destructive commands are blocked server-side; requires an account with operator role.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "Device IP"),
			"command": mergeDesc(strP(), "CLI command, e.g. 'show vlan brief'")}, "ip", "command"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/send-command",
				Body: map[string]any{"ip": str(a, "ip"), "command": str(a, "command")}}
		},
	},
	{
		Name:        "list_sites",
		Description: "List the configured sites (central + remote) with mode (central-poll/agent), subnets and last-seen time.",
		InputSchema: objP(map[string]any{}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/sites"}
		},
	},
	{
		Name:        "fortigate_status",
		Description: "Get live system status of a FortiGate firewall (version, HA, uptime, hostname) via REST API or SSH fallback.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "FortiGate IP (must be in inventory)")}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/status"}
		},
	},
	{
		Name:        "fortigate_interfaces",
		Description: "Get live interface state of a FortiGate: IPs, link status, speed, counters, VLANs, aggregates.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/interfaces"}
		},
	},
	{
		Name:        "fortigate_arp",
		Description: "Get the live ARP table of a FortiGate (IP <-> MAC on each interface).",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/arp"}
		},
	},
	{
		Name:        "fortigate_dhcp_leases",
		Description: "Get active DHCP leases from a FortiGate (client IP, MAC, hostname, expiry, interface).",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/dhcp-leases"}
		},
	},
	{
		Name:        "fortigate_device_inventory",
		Description: "Get the FortiOS device-identification inventory: every client the FortiGate has detected with MAC, IP, hostname, OS, ingress interface, online/offline state.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/device-inventory"}
		},
	},
	{
		Name:        "fortigate_policies",
		Description: "Get the configured firewall policies of a FortiGate (full policy table: src/dst interfaces and addresses, services, action, NAT, UTM profiles, logging).",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/policies"}
		},
	},
	{
		Name:        "fortigate_firewall_addresses",
		Description: "Get the firewall address book of a FortiGate (name, type, subnet/FQDN, comment) — slim cmdb read, useful to resolve object names used in policies.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/firewall/addresses"}
		},
	},
	{
		Name:        "fortigate_firewall_policy_objects",
		Description: "Get the firewall policy table of a FortiGate with only the fields relevant to observability (policyid, name, src/dst interfaces and addresses, service, action, status, logtraffic). Slimmer than fortigate_policies.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/firewall/policy-objects"}
		},
	},
	{
		Name:        "fortigate_firewall_services",
		Description: "Get the custom firewall services of a FortiGate (name, TCP/UDP port ranges, comment).",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/firewall/services"}
		},
	},
	{
		Name:        "fortigate_policy_lookup",
		Description: "Ask the FortiGate which firewall policy WOULD match a given flow (source IP, destination IP/FQDN, protocol, port) without generating traffic. Key tool for 'why can't client X reach site Y'.",
		InputSchema: objP(map[string]any{"ip": strP(),
			"src_ip":    mergeDesc(strP(), "Client source IP"),
			"dest":      mergeDesc(strP(), "Destination IP or FQDN"),
			"protocol":  mergeDesc(strP(), "TCP | UDP | ICMP (default TCP)"),
			"dest_port": mergeDesc(intP(), "Default 443")}, "ip", "src_ip", "dest"),
		BuildRequest: func(a map[string]any) Request {
			dp := any(443)
			if v, ok := a["dest_port"]; ok && v != nil {
				dp = v
			}
			return Request{Method: "POST", Path: "/api/fortigate/" + str(a, "ip") + "/policy-lookup",
				Body: map[string]any{"src_ip": str(a, "src_ip"), "dest": str(a, "dest"),
					"protocol": strOr(a, "protocol", "TCP"), "dest_port": dp}}
		},
	},
	{
		Name:        "fortigate_sessions",
		Description: "Get active sessions on a FortiGate, filterable by source IP, destination IP and destination port.",
		InputSchema: objP(map[string]any{"ip": strP(), "src_ip": strP(), "dst_ip": strP(),
			"dst_port": intP(),
			"count":    mergeDesc(intP(), "Max sessions (default 100)")}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/fortigate/" + str(a, "ip") + "/sessions",
				Body: present(a, "src_ip", "dst_ip", "dst_port", "count")}
		},
	},
	{
		Name:        "fortigate_routes",
		Description: "Get the live IPv4 routing table of a FortiGate.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/routes"}
		},
	},
	{
		Name:        "fortigate_traffic_logs",
		Description: "Query FortiGate forward traffic logs (what the firewall logged for a client/destination: allowed, denied, UTM verdicts). Filters optional.",
		InputSchema: objP(map[string]any{"ip": strP(), "src_ip": strP(), "dst_ip": strP(),
			"action": mergeDesc(strP(), "accept | deny | ..."),
			"count":  mergeDesc(intP(), "Max rows (default 100)")}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/fortigate/" + str(a, "ip") + "/logs",
				Body: present(a, "src_ip", "dst_ip", "action", "count")}
		},
	},
	{
		Name:        "fortigate_wifi_clients",
		Description: "List WiFi clients connected to FortiAPs managed by a FortiGate, with signal strength (RSSI/SNR), AP, SSID, data rates. Use for wireless disconnection troubleshooting.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/wifi/clients"}
		},
	},
	{
		Name:        "fortigate_managed_aps",
		Description: "List FortiAPs managed by a FortiGate: status, channel utilization, connected clients, firmware.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/wifi/aps"}
		},
	},
	{
		Name:        "fortigate_full_config",
		Description: "Get the complete live configuration of a FortiGate (full backup text). Large output; requires operator role.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/fortigate/" + str(a, "ip") + "/full-config"}
		},
	},
	{
		Name:        "fortigate_diagnose_client",
		Description: "One-shot diagnosis of a client (IP or MAC) through a FortiGate: device inventory, ARP, DHCP lease, active sessions, matching firewall policy toward an optional destination, recent traffic logs, WiFi state. Answers 'why can't this client reach X' / 'why does this client disconnect'.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "FortiGate IP"),
			"client":    mergeDesc(strP(), "Client IP or MAC address"),
			"dest":      mergeDesc(strP(), "Optional destination IP/FQDN for policy lookup"),
			"dest_port": mergeDesc(intP(), "Default 443"),
			"protocol":  mergeDesc(strP(), "TCP | UDP | ICMP (default TCP)")}, "ip", "client"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/fortigate/" + str(a, "ip") + "/diagnose-client",
				Body: present(a, "client", "dest", "dest_port", "protocol")}
		},
	},
	{
		Name:        "wlc_status",
		Description: "Get status of a Cisco wireless LAN controller (AireOS or Catalyst 9800): version, uptime, AP/client counts.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "WLC IP (must be in inventory)")}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/status"}
		},
	},
	{
		Name:        "wlc_ap_summary",
		Description: "List access points joined to a Cisco WLC: name, model, IP, clients, location, state.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/ap-summary"}
		},
	},
	{
		Name:        "wlc_client_summary",
		Description: "List wireless clients on a Cisco WLC with AP, WLAN/SSID, state and protocol.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/client-summary"}
		},
	},
	{
		Name:        "wlc_client_detail",
		Description: "Full detail for one wireless client by MAC: AP, SSID, RSSI/SNR, data rates, roaming/session history, policy state. Use for disconnection troubleshooting.",
		InputSchema: objP(map[string]any{"ip": strP(), "mac": mergeDesc(strP(), "Client MAC, any format")}, "ip", "mac"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/client/" + str(a, "mac")}
		},
	},
	{
		Name:        "wlc_wlan_summary",
		Description: "List WLANs/SSIDs configured on a Cisco WLC with status and security policy.",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/wlan-summary"}
		},
	},
	{
		Name:        "wlc_rogue_aps",
		Description: "List rogue/interfering access points detected by a Cisco WLC (possible cause of client disconnections).",
		InputSchema: objP(map[string]any{"ip": strP()}, "ip"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/rogue-aps"}
		},
	},
	{
		Name:        "wlc_diagnose_client",
		Description: "One-shot wireless diagnosis of a client (MAC) on a Cisco WLC: client detail (RSSI/SNR/AP/SSID), AP summary, WLAN summary and nearby rogue APs. Answers 'why do clients on this AP disconnect'.",
		InputSchema: objP(map[string]any{"ip": mergeDesc(strP(), "WLC IP"),
			"mac": mergeDesc(strP(), "Client MAC address")}, "ip", "mac"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/wlc/" + str(a, "ip") + "/diagnose-client/" + str(a, "mac")}
		},
	},
	{
		Name:        "generate_fortigate_config",
		Description: "Generate a hardened day-0 FortiOS configuration for a new FortiGate (zero-touch provisioning; does not touch any device). Same parameters as the FortiGate ZTP wizard.",
		InputSchema: objP(map[string]any{
			"hostname": strP(), "admin_user": strP(), "admin_password": strP(),
			"mgmt_interface": strP(), "mgmt_ip": strP(), "mgmt_mask": strP(),
			"wan_interface": strP(), "wan_mode": mergeDesc(strP(), "dhcp | static"),
			"wan_ip": strP(), "wan_mask": strP(), "wan_gw": strP(),
			"lan_interface": strP(), "lan_ip": strP(), "lan_mask": strP(),
			"dhcp_server": boolP(), "dhcp_start": strP(), "dhcp_end": strP(),
			"dns_primary": strP(), "dns_secondary": strP(),
			"ntp_servers":       map[string]any{"type": "array", "items": strP()},
			"syslog_server":     strP(),
			"lan_to_wan_policy": boolP(),
			"disable_wan_admin": boolP(),
			"banner":            strP(),
		}, "hostname"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/provisioner/fgt/generate", Body: a}
		},
	},
	{
		Name:        "generate_switch_config",
		Description: "Generate a hardened day-0 Cisco IOS/IOS-XE configuration for a new switch (does not touch any device). Accepts the same parameters as the 'Zero-Touch Switch' wizard.",
		InputSchema: objP(map[string]any{
			"hostname":  strP(),
			"role":      mergeDesc(strP(), "access | distribution"),
			"mgmt_vlan": intP(), "mgmt_ip": strP(), "mgmt_mask": strP(),
			"mgmt_gw": strP(), "admin_user": strP(), "admin_password": strP(),
			"enable_secret": strP(),
			"vlans": map[string]any{"type": "array", "items": map[string]any{"type": "object"},
				"description": "[{id, name}, ...]"},
			"access_ports":        map[string]any{"type": "array", "items": strP()},
			"access_vlan":         intP(),
			"trunk_ports":         map[string]any{"type": "array", "items": strP()},
			"trunk_allowed_vlans": strP(),
			"port_security":       boolP(),
			"dhcp_snooping":       boolP(),
			"ntp_servers":         map[string]any{"type": "array", "items": strP()},
			"syslog_server":       strP(),
		}, "hostname"),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "POST", Path: "/api/provisioner/generate", Body: a}
		},
	},
	{
		Name:        "get_top_talkers",
		Description: "Get the top bandwidth consumers (aggregated flow records) for a time window. Read-only, tenant-scoped, summarized (top-N only).",
		InputSchema: objP(map[string]any{
			"window": mergeDesc(strP(), "Time window, e.g. 15m, 24h (max 7d)"),
			"limit":  mergeDesc(intP(), "Max flows (default 20, max 100)"),
			"metric": mergeDesc(strP(), "'bytes' (default) or 'packets'")}),
		BuildRequest: func(a map[string]any) Request {
			limit := intOr(a, "limit", 20)
			if limit > 100 {
				limit = 100
			}
			return Request{Method: "GET", Path: "/api/observability/top", Query: map[string]string{
				"window": strOr(a, "window", "15m"), "limit": strconv.Itoa(limit),
				"metric": strOr(a, "metric", "bytes")}}
		},
	},
	{
		Name:        "get_anomalies",
		Description: "Get correlated security anomalies (blocked traffic matched with flow evidence and switch port). Read-only, tenant-scoped.",
		InputSchema: objP(map[string]any{
			"status": mergeDesc(strP(), "'new' (default), 'ack', 'resolved', 'all'"),
			"window": mergeDesc(strP(), "Time window, e.g. 24h (max 7d)")}),
		BuildRequest: func(a map[string]any) Request {
			return Request{Method: "GET", Path: "/api/observability/anomalies", Query: map[string]string{
				"status": strOr(a, "status", "new"), "window": strOr(a, "window", "24h"),
				"limit": "50"}}
		},
	},
}

// Catalog ritorna nome+descrizione di ogni tool per la rotta /api/mcp/settings.
func Catalog() []map[string]string {
	out := make([]map[string]string, 0, len(Tools))
	for _, t := range Tools {
		out = append(out, map[string]string{"name": t.Name, "description": t.Description})
	}
	return out
}
