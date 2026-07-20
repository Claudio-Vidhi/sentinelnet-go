package driver

import (
	"regexp"
	"strings"
)

// Regex replicate alla lettera da drivers/*.py. Il flag (?i) corrisponde a
// re.IGNORECASE nel Python; cisco_cbs ne è volutamente privo (usa [Vv]ersion).
var (
	reIOSVer      = regexp.MustCompile(`(?i), Version\s+([^,\r\n]+)`)
	reCBSVer      = regexp.MustCompile(`[Vv]ersion[:\s]+([0-9]+(?:\.[0-9]+)+)`)
	reWLCVer      = regexp.MustCompile(`(?i)Product Version\.*\s+(\S+)`)
	reArubaVer    = regexp.MustCompile(`(?i)Version\s+([0-9][\w.\-]+)`)
	reProcurveVer = regexp.MustCompile(`(?i)Firmware revision\s+:\s+(\S+)`)
	reJunosVer    = regexp.MustCompile(`(?i)Junos:\s*(\S+)`)
	reJunosAlt    = regexp.MustCompile(`(?i)JUNOS\b.*?\[([^\]]+)\]`)
	reFortiVer    = regexp.MustCompile(`(?i)Version:\s*\S+\s+v([^,\s]+)`)
	rePanosVer    = regexp.MustCompile(`(?i)sw-version:\s*(\S+)`)
)

// firstGroup applica re all'output e ritorna il gruppo 1 ripulito,
// o "" se non corrisponde. Equivale a match.group(1).strip() del Python.
func firstGroup(re *regexp.Regexp, out string) string {
	if m := re.FindStringSubmatch(out); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// orUnknown replica il `else "Unknown"` di ogni driver Python.
func orUnknown(v string) string {
	if v == "" {
		return "Unknown"
	}
	return v
}

// ---- Cisco IOS / IOS-XE (anche Catalyst 9800) ----

type CiscoIOS struct{}

func (CiscoIOS) GetVersion(r Runner) string {
	return orUnknown(firstGroup(reIOSVer, r.Run("show version")))
}
func (CiscoIOS) BackupCommand() string { return "show running-config" }
func (CiscoIOS) ARPCommand() string    { return "show ip arp" }

// ---- Cisco Business / Small Business (CBS220/250/350, SG/SF300-500) ----
// Alcuni di questi switch non rispondono come i Catalyst (prompt, paginazione
// e algoritmi SSH differenti): netmiko li tratta come 'cisco_s300'.

type CiscoCBS struct{}

func (CiscoCBS) GetVersion(r Runner) string {
	return orUnknown(firstGroup(reCBSVer, r.Run("show version")))
}
func (CiscoCBS) BackupCommand() string { return "show running-config" }
func (CiscoCBS) ARPCommand() string    { return "show arp" }

// ---- Cisco AireOS WLC (2500/3500/5500/8500, vWLC) ----

type CiscoWLC struct{}

func (CiscoWLC) GetVersion(r Runner) string {
	return orUnknown(firstGroup(reWLCVer, r.Run("show sysinfo")))
}
func (CiscoWLC) BackupCommand() string { return "show run-config commands" }
func (CiscoWLC) ARPCommand() string    { return "show arp switch" }

// ---- Aruba OS ----

type ArubaOS struct{}

func (ArubaOS) GetVersion(r Runner) string {
	return orUnknown(firstGroup(reArubaVer, r.Run("show version")))
}
func (ArubaOS) BackupCommand() string { return "show running-config" }
func (ArubaOS) ARPCommand() string    { return "show arp" }

// ---- HP / HPE ProCurve ----

type HPProcurve struct{}

func (HPProcurve) GetVersion(r Runner) string {
	return orUnknown(firstGroup(reProcurveVer, r.Run("show system")))
}
func (HPProcurve) BackupCommand() string { return "show run" }
func (HPProcurve) ARPCommand() string    { return "show arp" }

// ---- Juniper JunOS ----

type JuniperJunos struct{}

func (JuniperJunos) GetVersion(r Runner) string {
	out := r.Run("show version")
	if v := firstGroup(reJunosVer, out); v != "" {
		return v
	}
	return orUnknown(firstGroup(reJunosAlt, out))
}
func (JuniperJunos) BackupCommand() string { return "show configuration | display set" }
func (JuniperJunos) ARPCommand() string    { return "show arp no-resolve" }

// ---- Fortinet (fallback CLI: la via primaria è REST via fortigate_service) ----

type Fortinet struct{}

func (Fortinet) GetVersion(r Runner) string {
	return orUnknown(firstGroup(reFortiVer, r.Run("get system status")))
}
func (Fortinet) BackupCommand() string { return "show full-configuration" }

// ARPCommand: il Python non ha una voce fortinet in ARP_COMMANDS e ricade sul
// default "show arp", perché la raccolta ARP FortiGate passa dal ramo REST.
func (Fortinet) ARPCommand() string { return "show arp" }

// ---- Palo Alto PAN-OS ----

type PaloAlto struct{}

func (PaloAlto) GetVersion(r Runner) string {
	return orUnknown(firstGroup(rePanosVer, r.Run("show system info")))
}
func (PaloAlto) BackupCommand() string { return "show config running" }
func (PaloAlto) ARPCommand() string    { return "show arp all" }
