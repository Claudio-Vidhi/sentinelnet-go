// Package provision genera configurazioni "da zero" per apparati appena
// installati e le consegna via SSH o console seriale.
//
// BuildConfig è una funzione pura: nessun I/O, solo testo. La consegna vive
// altrove, così la generazione è verificabile riga per riga contro l'output
// dell'implementazione Python (vedi testdata/).
//
// L'output deve restare identico a quello del Python carattere per carattere:
// è una running-config che finisce su apparati veri, e una differenza
// "innocua" qui è una differenza di comportamento su uno switch in produzione.
package provision

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Ruoli ammessi per uno switch.
const (
	RoleAccess       = "access"
	RoleDistribution = "distribution"
)

// VLAN accetta sia {"id":10,"name":"DATA"} sia il solo id numerico: la UI
// invia entrambe le forme.
type VLAN struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// UnmarshalJSON gestisce le due notazioni. Un id senza nome diventa VLAN<id>,
// come nel Python.
func (v *VLAN) UnmarshalJSON(b []byte) error {
	var id int
	if err := json.Unmarshal(b, &id); err == nil {
		v.ID, v.Name = id, fmt.Sprintf("VLAN%d", id)
		return nil
	}
	var obj struct {
		ID   *json.Number `json:"id"`
		Name string       `json:"name"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	if obj.ID == nil {
		// Senza id la voce è inutilizzabile: si segnala con ID 0 e viene
		// scartata da BuildConfig, come fa il Python con "if vid is None".
		return nil
	}
	n, err := obj.ID.Int64()
	if err != nil {
		return err
	}
	v.ID = int(n)
	v.Name = obj.Name
	if v.Name == "" {
		v.Name = fmt.Sprintf("VLAN%d", v.ID)
	}
	return nil
}

// SVI è un'interfaccia di livello 3 su una VLAN (solo role=distribution).
type SVI struct {
	VLAN int    `json:"vlan"`
	IP   string `json:"ip"`
	Mask string `json:"mask"`
}

// AAAServer è un server RADIUS o TACACS+.
type AAAServer struct {
	IP       string `json:"ip"`
	Key      string `json:"key"`
	AuthPort int    `json:"auth_port"`
	AcctPort int    `json:"acct_port"`
}

// SNMPv3 raccoglie le credenziali SNMPv3.
type SNMPv3 struct {
	User     string `json:"user"`
	AuthPass string `json:"auth_pass"`
	PrivPass string `json:"priv_pass"`
	Group    string `json:"group"`
}

// SwitchConfig sono i parametri della running-config.
//
// I flag che nel Python hanno default True sono *bool e non bool: in Go un
// campo assente nel JSON diventa false, che qui significherebbe disattivare
// in silenzio una protezione (bpduguard, login_block, no_vstack...) solo
// perché la UI non ha inviato la chiave.
type SwitchConfig struct {
	Hostname string `json:"hostname"`
	Domain   string `json:"domain"`
	Role     string `json:"role"`

	MgmtVLAN int    `json:"mgmt_vlan"`
	MgmtIP   string `json:"mgmt_ip"`
	MgmtMask string `json:"mgmt_mask"`
	MgmtGw   string `json:"mgmt_gw"`

	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
	EnableSecret  string `json:"enable_secret"`

	SSHOnly *bool  `json:"ssh_only"`
	Banner  string `json:"banner"`

	NTPServers   []string `json:"ntp_servers"`
	SyslogServer string   `json:"syslog_server"`
	SNMPv3       *SNMPv3  `json:"snmpv3"`

	VLANs   []VLAN `json:"vlans"`
	VTPMode string `json:"vtp_mode"`
	STPMode string `json:"stp_mode"`

	Bpduguard         *bool  `json:"bpduguard"`
	PortSecurity      bool   `json:"port_security"`
	DHCPSnooping      bool   `json:"dhcp_snooping"`
	DHCPSnoopingVLANs string `json:"dhcp_snooping_vlans"`
	CDPEnabled        *bool  `json:"cdp_enabled"`
	LLDPEnabled       *bool  `json:"lldp_enabled"`

	AccessPorts []string `json:"access_ports"`
	AccessVLAN  int      `json:"access_vlan"`

	TrunkPorts        []string `json:"trunk_ports"`
	TrunkAllowedVLANs string   `json:"trunk_allowed_vlans"`
	UplinkPCID        int      `json:"uplink_pc_id"`

	LoginBlock         *bool `json:"login_block"`
	StormControl       bool  `json:"storm_control"`
	ErrdisableRecovery *bool `json:"errdisable_recovery"`
	NoVstack           *bool `json:"no_vstack"`

	SVIs           []SVI  `json:"svis"`
	EnableRouting  *bool  `json:"enable_routing"`
	DefaultRouteGw string `json:"default_route_gw"`

	AAAProtocol string      `json:"aaa_protocol"`
	AAAServers  []AAAServer `json:"aaa_servers"`
}

// boolOr risolve un flag opzionale al suo default.
func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// builder accumula le righe della configurazione.
type builder struct{ lines []string }

func (b *builder) add(format string, a ...any) {
	if len(a) == 0 {
		b.lines = append(b.lines, format)
		return
	}
	b.lines = append(b.lines, fmt.Sprintf(format, a...))
}

// sec apre una sezione commentata.
func (b *builder) sec(title string) {
	b.lines = append(b.lines, "!", "! --- "+title+" ---")
}

// BuildConfig assembla la running-config IOS/IOS-XE completa.
func BuildConfig(cfg SwitchConfig) string {
	hostname := strings.TrimSpace(cfg.Hostname)
	if hostname == "" {
		hostname = "Switch"
	}
	role := cfg.Role
	if role == "" {
		role = RoleAccess
	}

	b := &builder{}

	b.add("no service pad")
	b.add("service password-encryption")
	b.add("service timestamps debug datetime msec localtime")
	b.add("service timestamps log datetime msec localtime")
	b.add("service tcp-keepalives-in")
	b.add("service tcp-keepalives-out")
	b.add("!")
	b.add("hostname %s", hostname)
	b.add("!")
	b.add("no ip domain-lookup")
	if cfg.Domain != "" {
		b.add("ip domain-name %s", cfg.Domain)
	}
	b.add("no ip http server")
	b.add("no ip http secure-server")
	if boolOr(cfg.NoVstack, true) {
		// Smart Install (vstack) è un noto vettore d'attacco. Sui modelli che
		// non lo supportano il comando viene semplicemente rifiutato.
		b.add("no vstack")
	}

	b.sec("AUTENTICAZIONE LOCALE / ENABLE")
	if cfg.EnableSecret != "" {
		b.add("enable secret %s", cfg.EnableSecret)
	}
	if cfg.AdminUser != "" {
		pwd := cfg.AdminPassword
		if pwd == "" {
			pwd = "changeme"
		}
		b.add("username %s privilege 15 secret %s", cfg.AdminUser, pwd)
	}
	b.add("aaa new-model")

	buildAAA(b, cfg)

	if boolOr(cfg.LoginBlock, true) {
		// Anti brute-force: 5 tentativi falliti in 60s bloccano i login 120s.
		b.add("login block-for 120 attempts 5 within 60")
		b.add("login on-failure log")
		b.add("login on-success log")
	}

	sshOnly := boolOr(cfg.SSHOnly, true)
	if sshOnly {
		b.sec("SSH-ONLY MANAGEMENT")
		b.add("crypto key generate rsa modulus 2048")
		b.add("ip ssh version 2")
		b.add("ip ssh time-out 60")
		b.add("ip ssh authentication-retries 3")
	}

	b.sec("VTP")
	vtp := cfg.VTPMode
	if vtp == "" {
		vtp = "transparent"
	}
	b.add("vtp mode %s", vtp)

	vlans := validVLANs(cfg.VLANs)
	if len(vlans) > 0 {
		b.sec("VLAN DATABASE")
		for _, v := range vlans {
			b.add("vlan %d", v.ID)
			b.add(" name %s", v.Name)
		}
	}

	if cfg.MgmtVLAN != 0 {
		b.sec("INTERFACCIA DI MANAGEMENT")
		b.add("interface Vlan%d", cfg.MgmtVLAN)
		if cfg.MgmtIP != "" && cfg.MgmtMask != "" {
			b.add(" ip address %s %s", cfg.MgmtIP, cfg.MgmtMask)
		}
		b.add(" no shutdown")
		b.add("exit")
		if cfg.MgmtGw != "" && role == RoleAccess {
			b.add("ip default-gateway %s", cfg.MgmtGw)
		}
	}

	if role == RoleDistribution {
		b.sec("ROUTING MINIMO (DISTRIBUTION/CORE)")
		if boolOr(cfg.EnableRouting, true) {
			b.add("ip routing")
		}
		for _, svi := range cfg.SVIs {
			b.add("interface Vlan%d", svi.VLAN)
			b.add(" ip address %s %s", svi.IP, svi.Mask)
			b.add(" no shutdown")
			b.add("exit")
		}
		if cfg.DefaultRouteGw != "" {
			b.add("ip route 0.0.0.0 0.0.0.0 %s", cfg.DefaultRouteGw)
		}
	}

	b.sec("SPANNING-TREE")
	stp := cfg.STPMode
	if stp == "" {
		stp = "rapid-pvst"
	}
	b.add("spanning-tree mode %s", stp)
	b.add("spanning-tree extend system-id")
	bpduguard := boolOr(cfg.Bpduguard, true)
	if bpduguard {
		b.add("spanning-tree portfast bpduguard default")
	}

	if boolOr(cfg.ErrdisableRecovery, true) {
		var causes []string
		if bpduguard {
			causes = append(causes, "bpduguard")
		}
		if cfg.PortSecurity {
			causes = append(causes, "psecure-violation")
		}
		if cfg.StormControl {
			causes = append(causes, "storm-control")
		}
		if len(causes) > 0 {
			b.sec("ERRDISABLE AUTO-RECOVERY")
			for _, c := range causes {
				b.add("errdisable recovery cause %s", c)
			}
			b.add("errdisable recovery interval 300")
		}
	}

	if cfg.DHCPSnooping {
		b.sec("DHCP SNOOPING")
		b.add("ip dhcp snooping")
		if cfg.DHCPSnoopingVLANs != "" {
			b.add("ip dhcp snooping vlan %s", cfg.DHCPSnoopingVLANs)
		}
		b.add("no ip dhcp snooping information option")
	}

	b.sec("CDP / LLDP")
	if boolOr(cfg.CDPEnabled, true) {
		b.add("cdp run")
	} else {
		b.add("no cdp run")
	}
	if boolOr(cfg.LLDPEnabled, true) {
		b.add("lldp run")
	} else {
		b.add("no lldp run")
	}

	buildAccessPorts(b, cfg)
	buildTrunkPorts(b, cfg)

	if cfg.Banner != "" {
		b.sec("BANNER")
		b.add("banner motd ^C%s^C", cfg.Banner)
	}

	if len(cfg.NTPServers) > 0 {
		b.sec("NTP")
		for _, srv := range cfg.NTPServers {
			b.add("ntp server %s", srv)
		}
	}

	b.sec("LOGGING")
	b.add("logging buffered 16384")
	if cfg.SyslogServer != "" {
		b.add("logging host %s", cfg.SyslogServer)
		b.add("logging trap informational")
		// Senza una VLAN di management non c'è un'interfaccia sorgente da
		// dichiarare, e si ripiega su "logging on".
		if cfg.MgmtVLAN != 0 {
			b.add("logging source-interface Vlan%d", cfg.MgmtVLAN)
		} else {
			b.add("logging on")
		}
	}

	if cfg.SNMPv3 != nil && cfg.SNMPv3.User != "" {
		b.sec("SNMPv3")
		group := cfg.SNMPv3.Group
		if group == "" {
			group = "SNMP-GROUP"
		}
		b.add("snmp-server group %s v3 priv", group)
		authPass := cfg.SNMPv3.AuthPass
		if authPass == "" {
			authPass = "authpass123"
		}
		privPass := cfg.SNMPv3.PrivPass
		if privPass == "" {
			privPass = "privpass123"
		}
		b.add("snmp-server user %s %s v3 auth sha %s priv aes 128 %s",
			cfg.SNMPv3.User, group, authPass, privPass)
	}

	b.sec("HARDENING VTY / CONSOLE")
	b.add("line con 0")
	b.add(" login local")
	b.add(" exec-timeout 5 0")
	b.add("line vty 0 15")
	b.add(" login local")
	b.add(" exec-timeout 5 0")
	if sshOnly {
		b.add(" transport input ssh")
	} else {
		b.add(" transport input ssh telnet")
	}

	b.add("!")
	b.add("end")

	return strings.Join(b.lines, "\n") + "\n"
}

// validVLANs scarta le voci senza id, come il Python.
func validVLANs(in []VLAN) []VLAN {
	out := make([]VLAN, 0, len(in))
	for _, v := range in {
		if v.ID == 0 {
			continue
		}
		out = append(out, v)
	}
	return out
}

// buildAAA emette i server RADIUS/TACACS+ e il gruppo, oppure l'autenticazione
// locale quando non è configurato nessun server.
func buildAAA(b *builder, cfg SwitchConfig) {
	proto := cfg.AAAProtocol
	if (proto != "radius" && proto != "tacacs") || len(cfg.AAAServers) == 0 {
		b.add("aaa authentication login default local")
		b.add("aaa authorization exec default local")
		return
	}

	protoLabel, serverType, prefix := "tacacs+", "tacacs server", "TACACS"
	if proto == "radius" {
		protoLabel, serverType, prefix = "radius", "radius server", "RADIUS"
	}
	title := "AAA TACACS+"
	if proto == "radius" {
		title = "AAA RADIUS"
	}

	b.sec(title)
	names := make([]string, 0, len(cfg.AAAServers))
	for i, srv := range cfg.AAAServers {
		name := fmt.Sprintf("%s-%d", prefix, i+1)
		names = append(names, name)
		b.add("%s %s", serverType, name)
		if proto == "radius" {
			authPort := srv.AuthPort
			if authPort == 0 {
				authPort = 1812
			}
			acctPort := srv.AcctPort
			if acctPort == 0 {
				acctPort = 1813
			}
			b.add(" address ipv4 %s auth-port %d acct-port %d", srv.IP, authPort, acctPort)
		} else {
			b.add(" address ipv4 %s", srv.IP)
		}
		if srv.Key != "" {
			b.add(" key %s", srv.Key)
		}
	}
	b.add("aaa group server %s SENTINEL-AAA", protoLabel)
	for _, name := range names {
		b.add(" server name %s", name)
	}
	b.add("aaa authentication login default group SENTINEL-AAA local")
	b.add("aaa authorization exec default group SENTINEL-AAA local")
}

func buildAccessPorts(b *builder, cfg SwitchConfig) {
	if len(cfg.AccessPorts) == 0 {
		return
	}
	b.sec("PORTE ACCESS (EDGE)")
	for _, rng := range cfg.AccessPorts {
		b.add("interface range %s", rng)
		b.add(" switchport mode access")
		if cfg.AccessVLAN != 0 {
			b.add(" switchport access vlan %d", cfg.AccessVLAN)
		}
		b.add(" switchport nonegotiate")
		b.add(" spanning-tree portfast")
		b.add(" spanning-tree bpduguard enable")
		if cfg.PortSecurity {
			b.add(" switchport port-security")
			b.add(" switchport port-security maximum 2")
			b.add(" switchport port-security violation restrict")
			b.add(" switchport port-security aging time 2")
			b.add(" switchport port-security aging type inactivity")
		}
		if cfg.StormControl {
			b.add(" storm-control broadcast level 5.00")
			b.add(" storm-control action trap")
		}
		if cfg.DHCPSnooping {
			b.add(" ip dhcp snooping limit rate 15")
		}
		b.add(" no shutdown")
		b.add("exit")
	}
}

func buildTrunkPorts(b *builder, cfg SwitchConfig) {
	if len(cfg.TrunkPorts) == 0 {
		return
	}
	b.sec("PORTE TRUNK (UPLINK)")
	for _, rng := range cfg.TrunkPorts {
		b.add("interface range %s", rng)
		b.add(" switchport mode trunk")
		if cfg.TrunkAllowedVLANs != "" {
			b.add(" switchport trunk allowed vlan %s", cfg.TrunkAllowedVLANs)
		}
		b.add(" switchport nonegotiate")
		if cfg.DHCPSnooping {
			b.add(" ip dhcp snooping trust")
		}
		if cfg.UplinkPCID != 0 {
			b.add(" channel-group %d mode active", cfg.UplinkPCID)
		}
		b.add(" no shutdown")
		b.add("exit")
	}
	if cfg.UplinkPCID != 0 {
		// EtherChannel di uplink (LACP): l'interfaccia logica replica la
		// configurazione trunk dei membri.
		b.add("interface Port-channel%d", cfg.UplinkPCID)
		b.add(" switchport mode trunk")
		if cfg.TrunkAllowedVLANs != "" {
			b.add(" switchport trunk allowed vlan %s", cfg.TrunkAllowedVLANs)
		}
		b.add(" switchport nonegotiate")
		if cfg.DHCPSnooping {
			b.add(" ip dhcp snooping trust")
		}
		b.add(" no shutdown")
		b.add("exit")
	}
}

// ConfigCommands riduce la configurazione alle sole righe eseguibili,
// scartando commenti e righe vuote. È ciò che viene inviato all'apparato.
func ConfigCommands(configText string) []string {
	var out []string
	for _, ln := range strings.Split(configText, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "!") {
			continue
		}
		out = append(out, ln)
	}
	return out
}
