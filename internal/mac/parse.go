// Package mac: parser delle MAC address-table (CLI) e normalizzazione MAC.
package mac

import (
	"regexp"
	"strings"
)

type Entry struct {
	Mac       string
	Vlan      string
	Interface string
	Type      string // dynamic/static
}

// NormalizeMac porta un MAC in formato canonico aa:bb:cc:dd:ee:ff (minuscolo).
func NormalizeMac(raw string) string {
	r := strings.NewReplacer(":", "", "-", "", ".", "", " ", "")
	hex := strings.ToLower(r.Replace(raw))
	if len(hex) != 12 {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String()
}

var (
	// Cisco IOS: "  10    aaaa.bbbb.cccc    DYNAMIC     Gi1/0/5"
	reMacRow = regexp.MustCompile(`(?im)^\s*(\d+|All)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\w+)\s+(\S+)\s*$`)
	// Formato generico con separatori ":" o "-"
	reMacGeneric = regexp.MustCompile(`(?im)([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}`)
)

// ParseMacTable interpreta l'output di "show mac address-table" (Cisco/HPE).
func ParseMacTable(out string) []Entry {
	var entries []Entry
	for _, m := range reMacRow.FindAllStringSubmatch(out, -1) {
		entries = append(entries, Entry{
			Vlan:      m[1],
			Mac:       NormalizeMac(m[2]),
			Type:      strings.ToLower(m[3]),
			Interface: m[4],
		})
	}
	if len(entries) > 0 {
		return entries
	}
	// Fallback riga-per-riga per formati non standard.
	for _, line := range strings.Split(out, "\n") {
		macMatch := reMacGeneric.FindString(line)
		if macMatch == "" {
			continue
		}
		fields := strings.Fields(line)
		e := Entry{Mac: NormalizeMac(macMatch)}
		for _, f := range fields {
			if isVlan(f) && e.Vlan == "" {
				e.Vlan = f
			} else if isInterface(f) {
				e.Interface = f
			}
		}
		entries = append(entries, e)
	}
	return entries
}

// ParseBridgeDomain interpreta "show bridge-domain" (es. Catalyst 8000V):
// i MAC stanno associati a un bridge-domain e a un'interfaccia di servizio.
func ParseBridgeDomain(out string) []Entry {
	var entries []Entry
	var curBD string
	reBD := regexp.MustCompile(`(?i)^Bridge-domain\s+(\d+)`)
	reRow := regexp.MustCompile(`(?i)([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+\w+\s+(\S+)`)
	for _, line := range strings.Split(out, "\n") {
		if m := reBD.FindStringSubmatch(strings.TrimSpace(line)); len(m) == 2 {
			curBD = m[1]
			continue
		}
		if m := reRow.FindStringSubmatch(line); len(m) == 3 {
			entries = append(entries, Entry{
				Mac:       NormalizeMac(m[1]),
				Vlan:      curBD,
				Interface: m[2],
			})
		}
	}
	return entries
}

func isVlan(f string) bool {
	if f == "" {
		return false
	}
	for _, c := range f {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(f) <= 4
}

func isInterface(f string) bool {
	prefixes := []string{"Gi", "Fa", "Te", "Eth", "Et", "Po", "Fo", "Twe", "Hu", "mgmt"}
	for _, p := range prefixes {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	return false
}

// IsUplinkPort euristica: un uplink porta molti MAC (trunk). Il chiamante conta
// i MAC per interfaccia e chiama questa con la soglia.
func IsUplinkPort(macCount int) bool {
	return macCount > 5
}
