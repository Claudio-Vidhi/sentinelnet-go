package fwanalyzer

import (
	"regexp"
	"strings"
)

// Tipi di configurazione riconosciuti.
const (
	TypeIOS       = "ios"
	TypeFortiOS   = "fortios"
	TypePanOS     = "panos"
	TypeWLCAireOS = "wlc-aireos"
)

var (
	fortiosVendors = map[string]bool{"fortinet": true, "fortigate": true, "fortios": true}
	// cisco_wlc = AireOS; cisco_9800 = Catalyst 9800 (IOS-XE). Entrambi vanno
	// all'analizzatore WLC: AnalyzeWLCConfig distingue la piattaforma dal
	// contenuto. Instradare cisco_9800 qui è una DIVERGENZA voluta dal Python
	// (dove cisco_9800 -> ios) — vedi DIVERGENZE §11. NB: solo cisco_9800, non
	// il 'cisco' generico, che etichetterebbe come WLC ogni switch Cisco.
	wlcVendors   = map[string]bool{"cisco_wlc": true, "cisco_9800": true}
	panosVendors = map[string]bool{
		"palo_alto": true, "paloalto": true, "panos": true, "pan-os": true, "palo alto": true,
	}

	reFortiSystem = regexp.MustCompile(`(?m)^config system (global|interface)\b`)
	rePanosSet    = regexp.MustCompile(`(?m)^set (deviceconfig|mgt-config) `)
	reAireosCmd   = regexp.MustCompile(`(?m)^config (sysname|wlan|interface|radius|mobility|network)\b`)
	reAireosTable = regexp.MustCompile(`(?m)^System Name\.{3,}`)
)

// DetectConfigType determina il tipo di configurazione: ios | fortios | panos
// | wlc-aireos. Se il vendor di inventario è noto, decide da quello; altrimenti
// riconosce il formato dal contenuto. Tollerante: default "ios".
//
// Il vendor ha SEMPRE la precedenza sul contenuto: un vendor noto ma non
// firewall/WLC (es. "cisco") forza "ios" anche su una config che al
// contenuto sembrerebbe FortiOS. È il comportamento del Python, ed è voluto —
// l'inventario è più affidabile dello sniffing.
func DetectConfigType(content, vendor string) string {
	v := strings.ToLower(strings.TrimSpace(vendor))
	if v != "" {
		switch {
		case fortiosVendors[v]:
			return TypeFortiOS
		case wlcVendors[v]:
			return TypeWLCAireOS
		case panosVendors[v]:
			return TypePanOS
		default:
			return TypeIOS
		}
	}

	head := content
	if len(head) > 4000 {
		head = head[:4000]
	}
	switch {
	case strings.Contains(head, "#config-version="):
		return TypeFortiOS
	case reFortiSystem.MatchString(content):
		return TypeFortiOS
	case rePanosSet.MatchString(content):
		return TypePanOS
	case reAireosCmd.MatchString(content):
		return TypeWLCAireOS
	case reAireosTable.MatchString(content):
		return TypeWLCAireOS
	}
	return TypeIOS
}
