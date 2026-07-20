package provision

import "strings"

// FortiGateConfig sono i parametri della configurazione FortiOS "day-0" per
// un firewall appena installato (zero-touch), risultato dello stesso schema
// di FortiGateProvisioner.build_config in Python.
//
// I flag con default True nel Python sono *bool e non bool, per lo stesso
// motivo di SwitchConfig: un campo assente nel JSON diventerebbe false in
// Go, disattivando in silenzio funzioni di sicurezza (lockout,
// strong-crypto, policy LAN->WAN, blocco dell'accesso admin dal WAN,
// logging delle richieste REST API) che l'operatore si aspetta attive di
// default.
type FortiGateConfig struct {
	Hostname      string `json:"hostname"`
	Timezone      string `json:"timezone"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
	AdminTimeout  int    `json:"admin_timeout"`
	Lockout       *bool  `json:"lockout"`
	StrongCrypto  *bool  `json:"strong_crypto"`

	MgmtInterface   string `json:"mgmt_interface"`
	MgmtIP          string `json:"mgmt_ip"`
	MgmtMask        string `json:"mgmt_mask"`
	MgmtAllowaccess string `json:"mgmt_allowaccess"`

	WanInterface string `json:"wan_interface"`
	WanMode      string `json:"wan_mode"`
	WanIP        string `json:"wan_ip"`
	WanMask      string `json:"wan_mask"`
	WanGw        string `json:"wan_gw"`

	LanInterface string `json:"lan_interface"`
	LanIP        string `json:"lan_ip"`
	LanMask      string `json:"lan_mask"`

	DHCPServer bool   `json:"dhcp_server"`
	DHCPStart  string `json:"dhcp_start"`
	DHCPEnd    string `json:"dhcp_end"`

	DNSPrimary   string `json:"dns_primary"`
	DNSSecondary string `json:"dns_secondary"`

	NTPServers   []string         `json:"ntp_servers"`
	SyslogServer string           `json:"syslog_server"`
	SNMPv3       *FortiGateSNMPv3 `json:"snmpv3"`

	LanToWanPolicy  *bool  `json:"lan_to_wan_policy"`
	DisableWanAdmin *bool  `json:"disable_wan_admin"`
	Banner          string `json:"banner"`

	// Elementi ZTP (FortiOS 7.4 Administration Guide).
	APIUser          *FortiGateAPIUser     `json:"api_user"`
	CentralMgmt      *FortiGateCentralMgmt `json:"central_mgmt"`
	CSFGroup         string                `json:"csf_group"`
	NetflowCollector string                `json:"netflow_collector"`
	RestAPILogging   *bool                 `json:"rest_api_logging"`

	HA *FortiGateHA `json:"ha"`

	AAAProtocol string `json:"aaa_protocol"`
	AAAServerIP string `json:"aaa_server_ip"`
	AAAKey      string `json:"aaa_key"`
}

// FortiGateSNMPv3 raccoglie le credenziali SNMPv3 (nome distinto da SNMPv3
// dello switch: i due provisioner hanno campi diversi).
type FortiGateSNMPv3 struct {
	User     string `json:"user"`
	AuthPass string `json:"auth_pass"`
	PrivPass string `json:"priv_pass"`
}

// FortiGateAPIUser crea l'api-user REST per l'osservabilità SentinelNet dal
// day-0; il token va poi generato sul device con
// 'execute api-user generate-key <name>'.
type FortiGateAPIUser struct {
	Name       string   `json:"name"`
	Accprofile string   `json:"accprofile"`
	Trusthosts []string `json:"trusthosts"`
}

// FortiGateCentralMgmt configura system central-management (tunnel fgfm);
// con FortiManager richiede FmgIP.
type FortiGateCentralMgmt struct {
	Type  string `json:"type"`
	FmgIP string `json:"fmg_ip"`
}

// FortiGateHA descrive un cluster HA con interfaccia di management dedicata
// (ha-direct).
type FortiGateHA struct {
	GroupName     string `json:"group_name"`
	Mode          string `json:"mode"`
	Password      string `json:"password"`
	Hbdev         string `json:"hbdev"`
	Priority      int    `json:"priority"`
	MgmtInterface string `json:"mgmt_interface"`
	MgmtIP        string `json:"mgmt_ip"`
	MgmtMask      string `json:"mgmt_mask"`
}

// q quota un valore per la CLI FortiOS: tra virgolette se contiene uno
// spazio o è vuoto, altrimenti nudo. Riproduce esattamente _q() del Python.
func q(s string) string {
	if s == "" || strings.Contains(s, " ") {
		return `"` + s + `"`
	}
	return s
}

// strOr risolve una stringa opzionale al suo default, come "x or default" in
// Python (stringa vuota è falsy).
func strOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// BuildFortiGateConfig assembla la configurazione FortiOS "day-0" completa a
// partire da cfg. Funzione pura: nessun I/O, solo testo (vedi il commento di
// package in switch.go).
func BuildFortiGateConfig(cfg FortiGateConfig) string {
	hostname := strings.TrimSpace(cfg.Hostname)
	if hostname == "" {
		hostname = "FortiGate"
	}

	b := &builder{}

	// sec apre una sezione commentata: riga vuota + titolo, non "!" come per
	// gli switch IOS (FortiOS usa "#" per i commenti CLI).
	sec := func(title string) {
		b.add("")
		b.add("# --- %s ---", title)
	}

	sec("SYSTEM GLOBAL / HARDENING")
	b.add("config system global")
	b.add("    set hostname %s", q(hostname))
	b.add("    set timezone %s", q(strOr(cfg.Timezone, "Europe/Rome")))
	adminTimeout := cfg.AdminTimeout
	if adminTimeout == 0 {
		adminTimeout = 10
	}
	b.add("    set admintimeout %d", adminTimeout)
	if boolOr(cfg.StrongCrypto, true) {
		b.add("    set strong-crypto enable")
	}
	b.add("    set admin-https-redirect enable")
	if boolOr(cfg.Lockout, true) {
		// Anti brute-force: 3 tentativi falliti -> blocco 120s.
		b.add("    set admin-lockout-threshold 3")
		b.add("    set admin-lockout-duration 120")
	}
	if cfg.Banner != "" {
		b.add("    set post-login-banner enable")
	}
	b.add("end")
	if cfg.Banner != "" {
		b.add("config system replacemsg admin post_admin-disclaimer-text")
		b.add("    set buffer %s", q(cfg.Banner))
		b.add("end")
	}

	if cfg.AdminUser != "" {
		sec("ADMIN LOCALE AGGIUNTIVO")
		b.add("config system admin")
		b.add("    edit %s", q(cfg.AdminUser))
		b.add("        set password %s", q(strOr(cfg.AdminPassword, "changeme")))
		b.add("        set accprofile \"super_admin\"")
		b.add("    next")
		b.add("end")
	}

	buildFortiGateAAA(b, cfg, sec)

	central := cfg.CentralMgmt

	sec("INTERFACCE")
	b.add("config system interface")
	if cfg.MgmtInterface != "" && cfg.MgmtIP != "" {
		allowaccess := strOr(cfg.MgmtAllowaccess, "ping https ssh")
		// Il tunnel di management FortiManager/FortiGuard richiede 'fgfm'
		// sull'interfaccia da cui il device raggiunge il manager.
		if central != nil && central.Type != "" && !strings.Contains(allowaccess, "fgfm") {
			allowaccess += " fgfm"
		}
		b.add("    edit %s", q(cfg.MgmtInterface))
		b.add("        set mode static")
		b.add("        set ip %s %s", cfg.MgmtIP, strOr(cfg.MgmtMask, "255.255.255.0"))
		b.add("        set allowaccess %s", allowaccess)
		b.add("        set alias \"MGMT\"")
		b.add("    next")
	}
	if cfg.WanInterface != "" {
		b.add("    edit %s", q(cfg.WanInterface))
		if strOr(cfg.WanMode, "dhcp") == "static" && cfg.WanIP != "" {
			b.add("        set mode static")
			b.add("        set ip %s %s", cfg.WanIP, strOr(cfg.WanMask, "255.255.255.0"))
		} else {
			b.add("        set mode dhcp")
		}
		// Hardening: mai management esposto sul WAN (solo ping diagnostico).
		allow := "ping https ssh"
		if boolOr(cfg.DisableWanAdmin, true) {
			allow = "ping"
		}
		b.add("        set allowaccess %s", allow)
		b.add("        set alias \"WAN\"")
		b.add("        set role wan")
		b.add("    next")
	}
	if cfg.LanInterface != "" && cfg.LanIP != "" {
		b.add("    edit %s", q(cfg.LanInterface))
		b.add("        set mode static")
		b.add("        set ip %s %s", cfg.LanIP, strOr(cfg.LanMask, "255.255.255.0"))
		b.add("        set allowaccess ping")
		b.add("        set alias \"LAN\"")
		b.add("        set role lan")
		b.add("        set device-identification enable")
		b.add("    next")
	}
	b.add("end")

	if cfg.WanInterface != "" && strOr(cfg.WanMode, "dhcp") == "static" && cfg.WanGw != "" {
		sec("DEFAULT ROUTE")
		b.add("config router static")
		b.add("    edit 1")
		b.add("        set gateway %s", cfg.WanGw)
		b.add("        set device %s", q(cfg.WanInterface))
		b.add("    next")
		b.add("end")
	}

	if cfg.DNSPrimary != "" {
		sec("DNS")
		b.add("config system dns")
		b.add("    set primary %s", cfg.DNSPrimary)
		if cfg.DNSSecondary != "" {
			b.add("    set secondary %s", cfg.DNSSecondary)
		}
		b.add("end")
	}

	if len(cfg.NTPServers) > 0 {
		sec("NTP")
		b.add("config system ntp")
		b.add("    set ntpsync enable")
		b.add("    set type custom")
		b.add("    config ntpserver")
		for i, srv := range cfg.NTPServers {
			b.add("        edit %d", i+1)
			b.add("            set server %s", q(srv))
			b.add("        next")
		}
		b.add("    end")
		b.add("end")
	}

	if cfg.DHCPServer && cfg.LanInterface != "" && cfg.LanIP != "" && cfg.DHCPStart != "" && cfg.DHCPEnd != "" {
		sec("DHCP SERVER (LAN)")
		b.add("config system dhcp server")
		b.add("    edit 1")
		b.add("        set default-gateway %s", cfg.LanIP)
		b.add("        set netmask %s", strOr(cfg.LanMask, "255.255.255.0"))
		b.add("        set interface %s", q(cfg.LanInterface))
		b.add("        config ip-range")
		b.add("            edit 1")
		b.add("                set start-ip %s", cfg.DHCPStart)
		b.add("                set end-ip %s", cfg.DHCPEnd)
		b.add("            next")
		b.add("        end")
		if cfg.DNSPrimary != "" {
			b.add("        set dns-server1 %s", cfg.DNSPrimary)
		}
		b.add("    next")
		b.add("end")
	}

	if cfg.SyslogServer != "" {
		sec("SYSLOG")
		b.add("config log syslogd setting")
		b.add("    set status enable")
		b.add("    set server %s", q(cfg.SyslogServer))
		b.add("end")
	}

	if cfg.SNMPv3 != nil && cfg.SNMPv3.User != "" {
		sec("SNMPv3")
		b.add("config system snmp sysinfo")
		b.add("    set status enable")
		b.add("    set description %s", q(hostname))
		b.add("end")
		b.add("config system snmp user")
		b.add("    edit %s", q(cfg.SNMPv3.User))
		b.add("        set security-level auth-priv")
		b.add("        set auth-proto sha")
		b.add("        set auth-pwd %s", q(strOr(cfg.SNMPv3.AuthPass, "authpass123")))
		b.add("        set priv-proto aes")
		b.add("        set priv-pwd %s", q(strOr(cfg.SNMPv3.PrivPass, "privpass123")))
		b.add("    next")
		b.add("end")
	}

	if cfg.APIUser != nil && cfg.APIUser.Name != "" {
		sec("API USER (REST, osservabilita' SentinelNet)")
		b.add("config system api-user")
		b.add("    edit %s", q(cfg.APIUser.Name))
		b.add("        set accprofile %s", q(strOr(cfg.APIUser.Accprofile, "super_admin")))
		if len(cfg.APIUser.Trusthosts) > 0 {
			b.add("        config trusthost")
			for i, th := range cfg.APIUser.Trusthosts {
				b.add("            edit %d", i+1)
				b.add("                set ipv4-trusthost %s", th)
				b.add("            next")
			}
			b.add("        end")
		}
		b.add("    next")
		b.add("end")
		b.add("# Dopo il primo boot generare il token:")
		b.add("#   execute api-user generate-key %s", cfg.APIUser.Name)
	}

	if central != nil && central.Type != "" {
		sec("CENTRAL MANAGEMENT (ZTP)")
		b.add("config system central-management")
		b.add("    set type %s", central.Type)
		if central.Type == "fortimanager" && central.FmgIP != "" {
			b.add("    set fmg %s", q(central.FmgIP))
		}
		b.add("end")
	}

	if cfg.CSFGroup != "" {
		sec("SECURITY FABRIC")
		b.add("config system csf")
		b.add("    set status enable")
		b.add("    set group-name %s", q(cfg.CSFGroup))
		b.add("end")
	}

	if cfg.NetflowCollector != "" {
		sec("NETFLOW")
		b.add("config system netflow")
		b.add("    set collector-ip %s", cfg.NetflowCollector)
		b.add("end")
	}

	if boolOr(cfg.RestAPILogging, true) {
		sec("LOG RICHIESTE REST API")
		b.add("config log setting")
		b.add("    set rest-api-set enable")
		b.add("    set rest-api-get enable")
		b.add("end")
	}

	ha := cfg.HA
	if ha != nil && ha.GroupName != "" {
		sec("HIGH AVAILABILITY")
		b.add("config system ha")
		b.add("    set group-name %s", q(ha.GroupName))
		b.add("    set mode %s", strOr(ha.Mode, "a-p"))
		if ha.Password != "" {
			b.add("    set password %s", q(ha.Password))
		}
		if ha.Hbdev != "" {
			b.add("    set hbdev %s 50", q(ha.Hbdev))
		}
		b.add("    set session-pickup enable")
		b.add("    set override enable")
		priority := ha.Priority
		if priority == 0 {
			priority = 200
		}
		b.add("    set priority %d", priority)
		if ha.MgmtInterface != "" {
			b.add("    set ha-mgmt-status enable")
			b.add("    config ha-mgmt-interfaces")
			b.add("        edit 1")
			b.add("            set interface %s", q(ha.MgmtInterface))
			b.add("        next")
			b.add("    end")
			b.add("    set ha-direct enable")
		}
		b.add("end")
		if ha.MgmtInterface != "" && ha.MgmtIP != "" {
			b.add("config system interface")
			b.add("    edit %s", q(ha.MgmtInterface))
			b.add("        set ip %s %s", ha.MgmtIP, strOr(ha.MgmtMask, "255.255.255.0"))
			b.add("        set allowaccess ping https ssh fgfm")
			b.add("        set dedicated-to management")
			b.add("    next")
			b.add("end")
		}
	}

	if boolOr(cfg.LanToWanPolicy, true) && cfg.LanInterface != "" && cfg.WanInterface != "" {
		sec("FIREWALL POLICY LAN -> WAN (NAT)")
		b.add("config firewall policy")
		b.add("    edit 1")
		b.add("        set name \"LAN-to-WAN\"")
		b.add("        set srcintf %s", q(cfg.LanInterface))
		b.add("        set dstintf %s", q(cfg.WanInterface))
		b.add("        set srcaddr \"all\"")
		b.add("        set dstaddr \"all\"")
		b.add("        set action accept")
		b.add("        set schedule \"always\"")
		b.add("        set service \"ALL\"")
		b.add("        set nat enable")
		b.add("        set logtraffic all")
		b.add("    next")
		b.add("end")
	}

	// Come il Python: join, poi lstrip delle newline iniziali (la prima
	// sezione non deve lasciare una riga vuota in testa al file).
	out := strings.Join(b.lines, "\n")
	out = strings.TrimLeft(out, "\n")
	return out + "\n"
}

// buildFortiGateAAA emette i server RADIUS/TACACS+ e l'admin remoto quando
// configurato; a differenza dello switch, il FortiGate non ha un fallback
// "aaa authentication login default local" esplicito da emettere se assente
// (l'autenticazione locale è già il comportamento di default di FortiOS).
func buildFortiGateAAA(b *builder, cfg FortiGateConfig, sec func(string)) {
	aaaProtocol := strOr(cfg.AAAProtocol, "none")
	if (aaaProtocol != "radius" && aaaProtocol != "tacacs") || cfg.AAAServerIP == "" {
		return
	}

	serverName := "SENTINEL-TACACS"
	title := "AAA TACACS+"
	if aaaProtocol == "radius" {
		serverName = "SENTINEL-RADIUS"
		title = "AAA RADIUS"
	}
	groupName := "SENTINEL-AAA"

	sec(title)
	if aaaProtocol == "radius" {
		b.add("config user radius")
		b.add("    edit %s", q(serverName))
		b.add("        set server %s", cfg.AAAServerIP)
		if cfg.AAAKey != "" {
			b.add("        set secret %s", q(cfg.AAAKey))
		}
		b.add("    next")
		b.add("end")
	} else {
		b.add("config user tacacs+")
		b.add("    edit %s", q(serverName))
		b.add("        set server %s", cfg.AAAServerIP)
		if cfg.AAAKey != "" {
			b.add("        set key %s", q(cfg.AAAKey))
		}
		b.add("    next")
		b.add("end")
	}
	b.add("config user group")
	b.add("    edit %s", q(groupName))
	b.add("        set member %s", q(serverName))
	b.add("    next")
	b.add("end")
	b.add("config system admin")
	b.add("    edit %s", q("remote-"+strings.ToLower(serverName)))
	b.add("        set remote-auth enable")
	b.add("        set wildcard enable")
	b.add("        set remote-group %s", q(groupName))
	b.add("        set accprofile \"super_admin\"")
	b.add("    next")
	b.add("end")
}
