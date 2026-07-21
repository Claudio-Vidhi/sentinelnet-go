package configanalyzer

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// --- Cisco WLC (AireOS + IOS-XE/Catalyst 9800) -------------------------------
// Porta di analyze_wlc_config: analizza un WLC AireOS ('show run-config
// commands') e tollera il formato IOS-XE del Catalyst 9800, dove riusa il
// parser IOS come base e aggiunge l'estrazione dei blocchi 'wlan'.

// WLAN è una singola WLAN/SSID rilevata sul controller.
type WLAN struct {
	ID            string `json:"id"`
	SSID          string `json:"ssid"`
	Profile       string `json:"profile"`
	Enabled       bool   `json:"enabled"`
	Interface     string `json:"interface"`
	Security      string `json:"security"`
	TKIP          bool   `json:"tkip"`
	BroadcastSSID bool   `json:"broadcast_ssid"`
}

// WLCDynIface è un'interfaccia dinamica (AireOS): nome, VLAN, IP.
type WLCDynIface struct {
	Name string `json:"name"`
	Vlan string `json:"vlan"`
	IP   string `json:"ip"`
}

// WLCRadius è un server RADIUS auth/acct configurato.
type WLCRadius struct {
	Kind  string `json:"kind"`
	Index string `json:"index"`
	IP    string `json:"ip"`
	Port  string `json:"port"`
}

// WLCValidation raccoglie i controlli di sicurezza WLC.
type WLCValidation struct {
	OpenWlans        []string `json:"open_wlans"`
	LegacyTkipWlans  []string `json:"legacy_tkip_wlans"`
	DisabledWlans    []string `json:"disabled_wlans"`
	BroadcastSSIDOff []string `json:"broadcast_ssid_off"`
	ManagementHTTP   bool     `json:"management_http"`
}

// WLCAnalysis è il risultato dell'analisi. ios_base è presente solo per il
// Catalyst 9800 (IOS-XE), dove l'analisi IOS di base viene allegata.
type WLCAnalysis struct {
	Hostname          string        `json:"hostname"`
	Platform          string        `json:"platform"`
	Wlans             []WLAN        `json:"wlans"`
	DynamicInterfaces []WLCDynIface `json:"dynamic_interfaces"`
	RadiusServers     []WLCRadius   `json:"radius_servers"`
	MobilityGroup     string        `json:"mobility_group"`
	Validation        WLCValidation `json:"validation"`
	IOSBase           *Analysis     `json:"ios_base,omitempty"`
}

var (
	reWlcAireos    = regexp.MustCompile(`(?m)^config (sysname|wlan|interface|radius|mobility|network)\b`)
	reWlcToken     = regexp.MustCompile(`"[^"]*"|\S+`)
	reWlcWlanEnDis = regexp.MustCompile(`^config wlan (enable|disable) (\S+)`)
	reWlcRadiusAdd = regexp.MustCompile(`^config radius (auth|acct) add `)
	reWlcWlanBlock = regexp.MustCompile(`(?i)^wlan (\S+) (\d+) (\S+)`)
	reWlcHostname  = regexp.MustCompile(`(?m)^hostname (\S+)`)
)

// wlcTokens tokenizza rispettando le stringhe tra doppi apici (come
// _forti_tokens del Python: usato per 'config wlan create').
func wlcTokens(s string) []string {
	raw := reWlcToken.FindAllString(s, -1)
	out := make([]string, len(raw))
	for i, t := range raw {
		if len(t) >= 2 && strings.HasPrefix(t, `"`) && strings.HasSuffix(t, `"`) {
			out[i] = t[1 : len(t)-1]
		} else {
			out[i] = t
		}
	}
	return out
}

// AnalyzeWLCConfig analizza la config di un WLC Cisco. Riconosce AireOS ('show
// run-config commands') e tollera IOS-XE (Catalyst 9800): in quel caso riusa il
// parser IOS come base e aggiunge i blocchi 'wlan'. Pura, tollerante.
func AnalyzeWLCConfig(content string) WLCAnalysis {
	text := content
	isAireos := reWlcAireos.MatchString(text)

	// wlans e dyn_ifaces mantengono l'ordine d'inserimento (come i dict Python):
	// dyn_ifaces è emesso in quest'ordine, wlans è ordinato per id ma con
	// tie-break stabile sull'ordine d'inserimento.
	wlans := map[string]*WLAN{}
	wlanOrder := []string{}
	dyn := map[string]*WLCDynIface{}
	dynOrder := []string{}
	radius := []WLCRadius{}
	mobilityGroup := ""
	hostname := ""
	mgmtHTTP := false
	var base *Analysis

	wlan := func(wid string) *WLAN {
		w, ok := wlans[wid]
		if !ok {
			w = &WLAN{ID: wid, Security: "open", BroadcastSSID: true}
			wlans[wid] = w
			wlanOrder = append(wlanOrder, wid)
		}
		return w
	}
	dynIface := func(name string) *WLCDynIface {
		d, ok := dyn[name]
		if !ok {
			d = &WLCDynIface{Name: name}
			dyn[name] = d
			dynOrder = append(dynOrder, name)
		}
		return d
	}

	if isAireos {
		for _, raw := range strings.Split(text, "\n") {
			s := strings.TrimSpace(raw)
			low := strings.ToLower(s)
			switch {
			case strings.HasPrefix(low, "config sysname "):
				hostname = strings.TrimSpace(s[len("config sysname "):])
			case strings.HasPrefix(low, "config wlan create "):
				toks := wlcTokens(s) // config wlan create <id> <profile> [<ssid>]
				if len(toks) >= 4 {
					w := wlan(toks[3])
					if len(toks) > 4 {
						w.Profile = toks[4]
					}
					if len(toks) > 5 {
						w.SSID = toks[5]
					} else {
						w.SSID = w.Profile
					}
				}
			case reWlcWlanEnDis.MatchString(low):
				m := reWlcWlanEnDis.FindStringSubmatch(low)
				if m[2] != "all" {
					wlan(m[2]).Enabled = (m[1] == "enable")
				}
			case strings.HasPrefix(low, "config wlan interface "):
				toks := strings.Fields(s)
				if len(toks) >= 5 {
					wlan(toks[3]).Interface = toks[4]
				}
			case strings.HasPrefix(low, "config wlan broadcast-ssid disable "):
				f := strings.Fields(s)
				wlan(f[len(f)-1]).BroadcastSSID = false
			case strings.HasPrefix(low, "config wlan security "):
				toks := strings.Fields(low)
				wid := toks[len(toks)-1]
				rest := strings.Join(toks[3:len(toks)-1], " ")
				w := wlan(wid)
				switch {
				case rest == "wpa disable":
					w.Security = "open"
				case strings.Contains(rest, "wpa wpa2 enable"):
					w.Security = "WPA2"
				case strings.Contains(rest, "wpa wpa3 enable") || strings.Contains(rest, "wpa akm sae enable"):
					w.Security = "WPA3"
				case rest == "wpa enable" && w.Security == "open":
					w.Security = "WPA"
				case strings.Contains(rest, "wpa wpa1 enable"):
					w.Security = "WPA"
				}
				if strings.Contains(rest, "ciphers tkip enable") {
					w.TKIP = true
				}
			case strings.HasPrefix(low, "config interface create "):
				toks := strings.Fields(s)
				if len(toks) >= 4 {
					d := dynIface(toks[3])
					if len(toks) > 4 {
						d.Vlan = toks[4]
					}
				}
			case strings.HasPrefix(low, "config interface address "):
				toks := strings.Fields(s)
				// config interface address [dynamic-interface] <name> <ip> <mask> [gw]
				t := toks[3:]
				if len(t) > 0 && t[0] == "dynamic-interface" {
					t = t[1:]
				}
				if len(t) >= 3 {
					d := dynIface(t[0])
					d.IP = ipAddrToCidr(t[1:3])
				}
			case strings.HasPrefix(low, "config interface vlan "):
				toks := strings.Fields(s)
				if len(toks) >= 5 {
					dynIface(toks[3]).Vlan = toks[4]
				}
			case reWlcRadiusAdd.MatchString(low):
				toks := strings.Fields(s)
				if len(toks) >= 6 {
					port := ""
					if len(toks) > 6 {
						port = toks[6]
					}
					radius = append(radius, WLCRadius{
						Kind: toks[2], Index: toks[4], IP: toks[5], Port: port,
					})
				}
			case strings.HasPrefix(low, "config mobility group domain "):
				f := strings.Fields(s)
				mobilityGroup = f[len(f)-1]
			case low == "config network webmode enable":
				mgmtHTTP = true
			}
		}
	} else {
		// IOS-XE (Catalyst 9800): base IOS + blocchi 'wlan <profile> <id> <ssid>'.
		b := AnalyzeConfig(text)
		base = &b
		for _, blk := range iterBlocks(runningConfig(text)) {
			m := reWlcWlanBlock.FindStringSubmatch(strings.TrimSpace(blk.header))
			if m == nil {
				continue
			}
			w := wlan(m[2])
			w.Profile, w.SSID = m[1], m[3]
			w.Enabled = true
			sec := "WPA2"
			for _, bln := range blk.body {
				bl := strings.ToLower(strings.TrimSpace(bln))
				switch {
				case bl == "shutdown":
					w.Enabled = false
				case bl == "no security wpa":
					sec = "open"
				case strings.Contains(bl, "security wpa wpa3") || strings.Contains(bl, "sae"):
					sec = "WPA3"
				case strings.Contains(bl, "security wpa wpa1"):
					sec = "WPA"
				case strings.Contains(bl, "tkip"):
					w.TKIP = true
				case bl == "no broadcast-ssid":
					w.BroadcastSSID = false
				}
			}
			w.Security = sec
		}
		if m := reWlcHostname.FindStringSubmatch(text); m != nil {
			hostname = m[1]
		}
	}

	// wlan_list: ordine d'inserimento, poi ordinamento STABILE per id numerico
	// (0 se non numerico), come sorted(..., key=int if isdigit else 0) del Python.
	wlanList := make([]WLAN, 0, len(wlanOrder))
	for _, id := range wlanOrder {
		wlanList = append(wlanList, *wlans[id])
	}
	sort.SliceStable(wlanList, func(i, j int) bool {
		return wlanNumKey(wlanList[i].ID) < wlanNumKey(wlanList[j].ID)
	})

	dynList := make([]WLCDynIface, 0, len(dynOrder))
	for _, name := range dynOrder {
		dynList = append(dynList, *dyn[name])
	}

	label := func(w WLAN) string {
		if w.SSID != "" {
			return w.ID + " (" + w.SSID + ")"
		}
		return w.ID
	}
	val := WLCValidation{
		OpenWlans:        []string{},
		LegacyTkipWlans:  []string{},
		DisabledWlans:    []string{},
		BroadcastSSIDOff: []string{},
		ManagementHTTP:   mgmtHTTP,
	}
	for _, w := range wlanList {
		if w.Security == "open" {
			val.OpenWlans = append(val.OpenWlans, label(w))
		}
		if w.TKIP || w.Security == "WPA" {
			val.LegacyTkipWlans = append(val.LegacyTkipWlans, label(w))
		}
		if !w.Enabled {
			val.DisabledWlans = append(val.DisabledWlans, label(w))
		}
		if !w.BroadcastSSID {
			val.BroadcastSSIDOff = append(val.BroadcastSSIDOff, label(w))
		}
	}

	platform := "iosxe"
	if isAireos {
		platform = "aireos"
	}
	return WLCAnalysis{
		Hostname:          hostname,
		Platform:          platform,
		Wlans:             wlanList,
		DynamicInterfaces: dynList,
		RadiusServers:     radius,
		MobilityGroup:     mobilityGroup,
		Validation:        val,
		IOSBase:           base,
	}
}

// wlanNumKey rende la chiave d'ordinamento delle WLAN: id numerico o 0.
func wlanNumKey(id string) int {
	if isDigits(id) {
		n, _ := strconv.Atoi(id)
		return n
	}
	return 0
}
