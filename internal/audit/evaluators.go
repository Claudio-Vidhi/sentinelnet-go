package audit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func DetectVendor(configText string) string {
	lower := strings.ToLower(configText)
	if strings.Contains(lower, "config system") || strings.Contains(lower, "config firewall") || strings.Contains(lower, "config router") {
		return VendorFortiOS
	}
	if strings.Contains(lower, "version 1") || strings.Contains(lower, "line vty") || strings.Contains(lower, "interface gigabitethernet") || strings.Contains(lower, "service timestamps") {
		return VendorIOS
	}
	return VendorGeneric
}

// --- FortiOS Checks ---

func CheckFortiOSManagementProtocols(text string) (RuleOutcome, error) {
	lines := strings.Split(text, "\n")
	var ev []Evidence
	inIface := false
	currIface := ""
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "config system interface") {
			inIface = true
		} else if inIface && strings.HasPrefix(trimmed, "edit ") {
			currIface = strings.TrimPrefix(trimmed, "edit ")
		} else if inIface && strings.HasPrefix(trimmed, "set allowaccess ") {
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "telnet") || strings.Contains(lower, "http") && !strings.Contains(lower, "https") {
				ev = append(ev, Evidence{
					Line:    i + 1,
					Text:    trimmed,
					Context: currIface,
				})
			}
		} else if inIface && trimmed == "end" {
			inIface = false
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "Protocolli non sicuri (Telnet o HTTP in chiaro) abilitati sulle interfacce.",
			Evidence: ev,
		}, nil
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "Nessun protocollo di gestione non sicuro rilevato.",
	}, nil
}

func CheckFortiOSAnyAnyPolicy(text string) (RuleOutcome, error) {
	lines := strings.Split(text, "\n")
	var ev []Evidence
	inPolicy := false
	currPol := ""
	srcAll, dstAll, svcAll := false, false, false
	actAccept := false

	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "config firewall policy") {
			inPolicy = true
		} else if inPolicy && strings.HasPrefix(trimmed, "edit ") {
			currPol = strings.TrimPrefix(trimmed, "edit ")
			srcAll, dstAll, svcAll, actAccept = false, false, false, false
		} else if inPolicy && strings.HasPrefix(trimmed, "set srcaddr ") && strings.Contains(trimmed, "all") {
			srcAll = true
		} else if inPolicy && strings.HasPrefix(trimmed, "set dstaddr ") && strings.Contains(trimmed, "all") {
			dstAll = true
		} else if inPolicy && strings.HasPrefix(trimmed, "set service ") && strings.Contains(trimmed, "ALL") {
			svcAll = true
		} else if inPolicy && strings.HasPrefix(trimmed, "set action ") && strings.Contains(trimmed, "accept") {
			actAccept = true
		} else if inPolicy && trimmed == "next" {
			if srcAll && dstAll && svcAll && actAccept {
				ev = append(ev, Evidence{
					Line:    i + 1,
					Text:    fmt.Sprintf("policy %s: any-to-any con action accept", currPol),
					Context: currPol,
				})
			}
		} else if inPolicy && trimmed == "end" {
			inPolicy = false
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "Rilevata policy permissiva any-to-any accept.",
			Evidence: ev,
		}, nil
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "Nessuna policy permissiva any-to-any accept rilevata.",
	}, nil
}

func CheckFortiOSTLSVersion(text string) (RuleOutcome, error) {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "set admin-https-ssl-versions ") {
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "tlsv1-0") || strings.Contains(lower, "tlsv1-1") || strings.Contains(lower, "sslv3") {
				return RuleOutcome{
					Status: StatusFail,
					Message: "Versioni TLS obsolete o insicure abilitate per la GUI/API.",
					Evidence: []Evidence{{Line: i + 1, Text: trimmed}},
				}, nil
			}
			return RuleOutcome{
				Status: StatusPass,
				Message: "Versioni TLS configurate in modo sicuro (TLS 1.2+).",
			}, nil
		}
	}
	return RuleOutcome{
		Status:  StatusWarn,
		Message: "Direttiva admin-https-ssl-versions non impostata esplicitamente.",
	}, nil
}

func CheckFortiOSIdleTimeout(text string) (RuleOutcome, error) {
	lines := strings.Split(text, "\n")
	re := regexp.MustCompile(`set\s+admintimeout\s+(\d+)`)
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if m := re.FindStringSubmatch(trimmed); len(m) == 2 {
			mins, _ := strconv.Atoi(m[1])
			if mins > 10 {
				return RuleOutcome{
					Status:  StatusWarn,
					Message: fmt.Sprintf("Timeout di inattivita' elevato (%d minuti, consigliato <= 10).", mins),
					Evidence: []Evidence{{Line: i + 1, Text: trimmed}},
				}, nil
			}
			return RuleOutcome{
				Status:  StatusPass,
				Message: fmt.Sprintf("Timeout di inattivita' console configurato a %d minuti.", mins),
			}, nil
		}
	}
	return RuleOutcome{
		Status:  StatusWarn,
		Message: "Direttiva admintimeout non specificata (default di fabbrica).",
	}, nil
}

func CheckFortiOSSNMPCommunity(text string) (RuleOutcome, error) {
	lines := strings.Split(text, "\n")
	var ev []Evidence
	inSNMP := false
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "config system snmp community") {
			inSNMP = true
		} else if inSNMP && (strings.HasPrefix(trimmed, "edit ") || strings.HasPrefix(trimmed, "set name ")) {
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "public") || strings.Contains(lower, "private") {
				ev = append(ev, Evidence{Line: i + 1, Text: trimmed})
			}
		} else if inSNMP && trimmed == "end" {
			inSNMP = false
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "Community SNMP di default ('public'/'private') configurate.",
			Evidence: ev,
		}, nil
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "Nessuna community SNMP di default rilevata.",
	}, nil
}

func CheckFortiOSPasswordPolicy(text string) (RuleOutcome, error) {
	if !strings.Contains(text, "config system password-policy") {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "Password policy per gli amministratori non configurata.",
		}, nil
	}
	if strings.Contains(text, "set status enable") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "Password policy attiva per gli amministratori.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusWarn,
		Message: "Password policy presente ma non abilitata.",
	}, nil
}

func CheckFortiOSNTP(text string) (RuleOutcome, error) {
	if strings.Contains(text, "config system ntp") && strings.Contains(text, "set ntpsync enable") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "Sincronizzazione NTP attiva.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusFail,
		Message: "Sincronizzazione oraria NTP non configurata o disabilitata.",
	}, nil
}

// --- Cisco IOS Checks ---

func CheckIOSVTYTransportSSH(text string) (RuleOutcome, error) {
	lines := strings.Split(text, "\n")
	var ev []Evidence
	inVTY := false
	hasTransportSSH := false

	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "line vty ") {
			inVTY = true
		} else if inVTY && strings.HasPrefix(trimmed, "transport input ") {
			if strings.Contains(trimmed, "telnet") || strings.Contains(trimmed, "all") {
				ev = append(ev, Evidence{Line: i + 1, Text: trimmed})
			} else if strings.Contains(trimmed, "ssh") {
				hasTransportSSH = true
			}
		} else if inVTY && (strings.HasPrefix(trimmed, "line ") || strings.HasPrefix(trimmed, "interface ") || trimmed == "!") {
			inVTY = false
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "Telnet o protocolli non cifrati abilitati sulle linee VTY.",
			Evidence: ev,
		}, nil
	}
	if !hasTransportSSH {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "Direttiva 'transport input ssh' non rilevata esplicitamente sulle linee VTY.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "Linee VTY protette da SSH esclusivo.",
	}, nil
}

func CheckIOSVTYAccessClass(text string) (RuleOutcome, error) {
	if strings.Contains(text, "access-class ") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "Access-class configurata sulle linee di gestione.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusFail,
		Message: "Nessuna access-class configurata per restringere gli IP di gestione VTY.",
	}, nil
}

func CheckIOSAAAModel(text string) (RuleOutcome, error) {
	if strings.Contains(text, "aaa new-model") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "Modello AAA abilitato (aaa new-model).",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusFail,
		Message: "Modello AAA non abilitato.",
	}, nil
}

func CheckIOSEnableSecret(text string) (RuleOutcome, error) {
	if strings.Contains(text, "enable secret") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "Password di enable protetta da hash forte (enable secret).",
		}, nil
	}
	if strings.Contains(text, "enable password") {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "Uso di 'enable password' invece di 'enable secret'.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusWarn,
		Message: "Nessuna password di enable rilevata.",
	}, nil
}

func CheckIOSSSHVersion(text string) (RuleOutcome, error) {
	if strings.Contains(text, "ip ssh version 2") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "SSH versione 2 imposto esplicitamente.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusWarn,
		Message: "SSH versione 2 non imposto esplicitamente (ip ssh version 2).",
	}, nil
}

func CheckIOSLoggingHost(text string) (RuleOutcome, error) {
	if strings.Contains(text, "logging host ") || strings.Contains(text, "logging server ") {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "Inoltro log verso collector remoto configurato.",
		}, nil
	}
	return RuleOutcome{
		Status:  StatusFail,
		Message: "Nessun server syslog remoto configurato (logging host).",
	}, nil
}
