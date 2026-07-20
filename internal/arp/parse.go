// Package arp: parsing delle tabelle ARP dei gateway L3.
// Porta di collectors/arp_collector.py.
//
// Nel mondo reale il gateway di una VLAN può essere uno switch L3 (SVI), un
// firewall o un router: la tabella ARP autorevole sta su chi ruota la VLAN.
// Il parser è volutamente generico riga-per-riga, così un solo formato copre
// Cisco, FortiOS, HP, Juniper e PAN-OS.
package arp

import (
	"regexp"
	"strings"
)

type Entry struct {
	MAC       string
	IP        string
	VLAN      string
	Interface string
}

var (
	// Notazioni MAC accettate:
	//   aa:bb:cc:dd:ee:ff / aa-bb-cc-dd-ee-ff   (sei gruppi da due)
	//   aabb.ccdd.eeff / aabb-ccdd-eeff          (tre gruppi da quattro)
	//   001a4b-2c3d4e                            (HP/ProCurve, due gruppi da sei)
	//
	// Le ultime due forme non sono riconosciute dal Python, che perde
	// silenziosamente le righe ARP degli switch HP: vedi
	// docs/DIVERGENZE-DAL-PYTHON.md §2.
	reMACAny = regexp.MustCompile(`\b([0-9a-fA-F]{2}([:\-][0-9a-fA-F]{2}){5}` +
		`|[0-9a-fA-F]{4}([.\-][0-9a-fA-F]{4}){2}` +
		`|[0-9a-fA-F]{6}-[0-9a-fA-F]{6})\b`)
	reIP     = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
	reVlanIf = regexp.MustCompile(`(?i)\b(?:vlan|vl)\s*(\d+)\b`)
)

// ParseOutput estrae i binding (ip, mac) da qualunque formato ARP testuale,
// es. Cisco "Internet 10.0.0.1 5 aabb.ccdd.eeff ARPA Vlan10".
// L'interfaccia è l'ultimo token della riga se non numerico; la VLAN è dedotta
// da "VlanN".
func ParseOutput(text string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		macM := reMACAny.FindStringSubmatch(line)
		ipM := reIP.FindStringSubmatch(line)
		if macM == nil || ipM == nil {
			continue
		}
		macRaw := macM[1]
		if isDiscardableMAC(macRaw) {
			continue
		}
		vlan := ""
		if m := reVlanIf.FindStringSubmatch(line); m != nil {
			vlan = m[1]
		}
		// Euristica interfaccia, valida per Cisco/FortiOS/HP: se sbaglia resta
		// comunque il binding mac<->ip, che è il dato che conta.
		iface := ""
		if tokens := strings.Fields(line); len(tokens) > 0 {
			last := tokens[len(tokens)-1]
			if !isAllDigits(last) {
				iface = last
			}
		}
		if iface == macRaw || iface == ipM[1] {
			iface = ""
		}
		out = append(out, Entry{MAC: macRaw, IP: ipM[1], VLAN: vlan, Interface: iface})
	}
	return out
}

// isDiscardableMAC scarta broadcast e indirizzi nulli, in QUALUNQUE notazione.
//
// Il Python sostituisce '-' con ':' prima del confronto, lasciando i due punti
// nella stringa: di fatto intercetta solo la forma puntata e lascia passare
// ff:ff:ff:ff:ff:ff come se fosse un client reale. Vedi
// docs/DIVERGENZE-DAL-PYTHON.md §1.
func isDiscardableMAC(mac string) bool {
	s := strings.Map(func(r rune) rune {
		if r == ':' || r == '-' || r == '.' {
			return -1
		}
		return r
	}, strings.ToLower(mac))
	return s == "ffffffffffff" || s == "000000000000"
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
