package audit

import (
	"strings"
)

var CISFortiOSRules = []BenchmarkRule{
	{
		ID:        "AUD-CIS-01",
		Vendor:    VendorFortiOS,
		Ref:       "2.4.5",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Protocolli di gestione non sicuri (Telnet / HTTP)",
			"en": "Insecure management protocols (Telnet / HTTP)",
		},
		Severity:    "CRITICAL",
		Category:    "Hardening",
		AuditCLI:    "config system interface\n    show full-configuration | grep allowaccess",
		Remediation: "config system interface / edit <port> / set allowaccess ssh https",
		ChecksDoc:   "Verifica che Telnet e HTTP in chiaro non siano abilitati su allowaccess.",
		Check:       CheckFortiOSManagementProtocols,
	},
	{
		ID:        "AUD-CIS-02",
		Vendor:    VendorFortiOS,
		Ref:       "3.2",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Policy permissiva any-to-any",
			"en": "Permissive any-to-any policy",
		},
		Severity:    "CRITICAL",
		Category:    "Access Rules",
		AuditCLI:    "show full-configuration firewall policy",
		Remediation: "Specificare srcaddr, dstaddr e service espliciti.",
		ChecksDoc:   "Rileva policy con sorgente all, destinazione all e servizio ALL.",
		Check:       CheckFortiOSAnyAnyPolicy,
	},
	{
		ID:        "AUD-CIS-03",
		Vendor:    VendorFortiOS,
		Ref:       "2.1.10",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Versione TLS della GUI di amministrazione e API REST",
			"en": "TLS version of the admin GUI and REST API",
		},
		Severity:    "HIGH",
		Category:    "Encryption",
		AuditCLI:    "config system global\n    show full-configuration | grep admin-https-ssl-versions",
		Remediation: "config system global / set admin-https-ssl-versions tlsv1-2 tlsv1-3",
		ChecksDoc:   "Verifica che TLS 1.2 o 1.3 siano imposti.",
		Check:       CheckFortiOSTLSVersion,
	},
	{
		ID:        "AUD-CIS-04",
		Vendor:    VendorFortiOS,
		Ref:       "2.4.4",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Timeout di inattivita' della console di gestione",
			"en": "Idle timeout on the management console",
		},
		Severity:    "MEDIUM",
		Category:    "Hardening",
		AuditCLI:    "config system global\n    show full-configuration | grep admintimeout",
		Remediation: "config system global / set admintimeout 5",
		ChecksDoc:   "Verifica che il timeout di inattivita' sia configurato a <= 10 minuti.",
		Check:       CheckFortiOSIdleTimeout,
	},
	{
		ID:        "AUD-CIS-05",
		Vendor:    VendorFortiOS,
		Ref:       "2.3.1",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Community SNMP v1/v2c di default",
			"en": "Default SNMP v1/v2c communities",
		},
		Severity:    "HIGH",
		Category:    "Management",
		AuditCLI:    "config system snmp community\n    show full-configuration",
		Remediation: "Disabilitare SNMP v1/v2c e configurare SNMPv3.",
		ChecksDoc:   "Verifica l'assenza di community public/private.",
		Check:       CheckFortiOSSNMPCommunity,
	},
	{
		ID:        "AUD-CIS-11",
		Vendor:    VendorFortiOS,
		Ref:       "2.1.4",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Sincronizzazione oraria (NTP)",
			"en": "Time synchronisation (NTP)",
		},
		Severity:    "MEDIUM",
		Category:    "Logging",
		AuditCLI:    "config system ntp\n    show full-configuration",
		Remediation: "config system ntp / set ntpsync enable / set type custom",
		ChecksDoc:   "Verifica che la sincronizzazione NTP sia attiva.",
		Check:       CheckFortiOSNTP,
	},
	{
		ID:        "AUD-CIS-18",
		Vendor:    VendorFortiOS,
		Ref:       "2.2.1",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Robustezza della policy password",
			"en": "Password policy strength",
		},
		Severity:    "HIGH",
		Category:    "Identity",
		AuditCLI:    "config system password-policy\n    show full-configuration",
		Remediation: "config system password-policy / set status enable",
		ChecksDoc:   "Verifica che la password policy per gli amministratori sia attiva.",
		Check:       CheckFortiOSPasswordPolicy,
	},
}

var CISIOSRules = []BenchmarkRule{
	{
		ID:        "AUD-IOS-01",
		Vendor:    VendorIOS,
		Ref:       "1.1.1",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Modello AAA non attivo",
			"en": "AAA model not enabled",
		},
		Severity:    "HIGH",
		Category:    "Identity",
		AuditCLI:    "show running-config | include aaa new-model",
		Remediation: "aaa new-model",
		ChecksDoc:   "Verifica la presenza di aaa new-model.",
		Check:       CheckIOSAAAModel,
	},
	{
		ID:        "AUD-IOS-04",
		Vendor:    VendorIOS,
		Ref:       "1.2.2",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Protocolli non cifrati sulle linee vty",
			"en": "Unencrypted protocols on the vty lines",
		},
		Severity:    "CRITICAL",
		Category:    "Hardening",
		AuditCLI:    "show running-config | section line vty",
		Remediation: "line vty 0 15 / transport input ssh",
		ChecksDoc:   "Verifica che solo SSH sia permesso su VTY.",
		Check:       CheckIOSVTYTransportSSH,
	},
	{
		ID:        "AUD-IOS-05",
		Vendor:    VendorIOS,
		Ref:       "1.2.5",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Access-class assente sulle linee vty",
			"en": "Access-class missing on the vty lines",
		},
		Severity:    "CRITICAL",
		Category:    "Access Rules",
		AuditCLI:    "show running-config | section line vty",
		Remediation: "line vty 0 15 / access-class <ACL gestione> in",
		ChecksDoc:   "Verifica che una access-class sia applicata a VTY.",
		Check:       CheckIOSVTYAccessClass,
	},
	{
		ID:        "AUD-IOS-12",
		Vendor:    VendorIOS,
		Ref:       "1.4.1",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Password di enable non protetta da hash forte",
			"en": "Enable password not protected by a strong hash",
		},
		Severity:    "CRITICAL",
		Category:    "Identity",
		AuditCLI:    "show running-config | include enable",
		Remediation: "enable algorithm-type sha256 secret <password>",
		ChecksDoc:   "Verifica che enable secret sia utilizzato invece di enable password.",
		Check:       CheckIOSEnableSecret,
	},
	{
		ID:        "AUD-IOS-19",
		Vendor:    VendorIOS,
		Ref:       "2.1.1.2",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Versione del protocollo SSH",
			"en": "SSH protocol version",
		},
		Severity:    "HIGH",
		Category:    "Encryption",
		AuditCLI:    "show running-config | include ip ssh version",
		Remediation: "ip ssh version 2",
		ChecksDoc:   "Verifica che ip ssh version 2 sia configurato.",
		Check:       CheckIOSSSHVersion,
	},
	{
		ID:        "AUD-IOS-27",
		Vendor:    VendorIOS,
		Ref:       "2.2.4",
		Level:     1,
		Automated: true,
		Title: map[string]string{
			"it": "Inoltro dei log verso un collector remoto",
			"en": "Log forwarding to a remote collector",
		},
		Severity:    "HIGH",
		Category:    "Logging",
		AuditCLI:    "show running-config | include logging host",
		Remediation: "logging host <ip collector>",
		ChecksDoc:   "Verifica la presenza di logging host per syslog remoto.",
		Check:       CheckIOSLoggingHost,
	},
}

var Benchmarks = map[string][]BenchmarkRule{
	"cis":  append(append([]BenchmarkRule{}, CISFortiOSRules...), CISIOSRules...),
	"nist": append(append([]BenchmarkRule{}, CISFortiOSRules...), CISIOSRules...),
	"pci":  append(append([]BenchmarkRule{}, CISFortiOSRules...), CISIOSRules...),
}

func BenchmarkTitle(bm string) string {
	switch strings.ToLower(bm) {
	case "cis":
		return "CIS Benchmark v1.0 / v2.2"
	case "nist":
		return "NIST SP 800-53 Rev. 5"
	case "pci":
		return "PCI-DSS v4.0"
	default:
		return "Security Benchmark"
	}
}

// RunNetSecAudit esegue la scansione di compliance su una configurazione.
func RunNetSecAudit(configText, deviceName, benchmark, lang string) (AuditScanResult, error) {
	if lang == "" {
		lang = "it"
	}
	bmKey := strings.ToLower(strings.TrimSpace(benchmark))
	if bmKey == "" {
		bmKey = "cis"
	}
	rulesList, ok := Benchmarks[bmKey]
	if !ok {
		bmKey = "cis"
		rulesList = Benchmarks["cis"]
	}

	vendor := DetectVendor(configText)
	var evaluatedRules []RuleResult

	for _, r := range rulesList {
		if r.Vendor != vendor && vendor != VendorGeneric {
			continue
		}
		title := r.Title[lang]
		if title == "" {
			title = r.Title["it"]
		}
		remStr := ""
		if str, ok := r.Remediation.(string); ok {
			remStr = str
		} else if m, ok := r.Remediation.(map[string]string); ok {
			remStr = m[lang]
			if remStr == "" {
				remStr = m["it"]
			}
		}

		outcome, err := r.Check(configText)
		if err != nil {
			outcome = RuleOutcome{Status: StatusUnknown, Message: "Errore durante la valutazione della regola."}
		}

		evaluatedRules = append(evaluatedRules, RuleResult{
			ID:          r.ID,
			Title:       title,
			Severity:    r.Severity,
			Category:    r.Category,
			Vendor:      r.Vendor,
			Ref:         r.Ref,
			Level:       r.Level,
			Automated:   r.Automated,
			Status:      outcome.Status,
			Message:     outcome.Message,
			Evidence:    outcome.Evidence,
			AuditCLI:    r.AuditCLI,
			Remediation: remStr,
		})
	}

	score, summary := CalculateScore(evaluatedRules)
	grade := ScoreGrade(score)

	return AuditScanResult{
		DeviceName:     deviceName,
		Benchmark:      bmKey,
		BenchmarkTitle: BenchmarkTitle(bmKey),
		Vendor:         vendor,
		Lang:           lang,
		Score:          score,
		Grade:          grade,
		Summary:        summary,
		Rules:          evaluatedRules,
	}, nil
}
