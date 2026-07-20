package mac

import (
	"regexp"
	"strings"
)

// IfMac è il MAC di un'interfaccia propria dello switch.
type IfMac struct {
	Interface string
	Mac       string
}

var (
	// Riga di intestazione interfaccia: "GigabitEthernet1/0/1 is up, line protocol is up"
	reIfHdr = regexp.MustCompile(`(?i)^(\S+) is `)
	// "  Hardware is ..., address is aabb.ccdd.eeff (bia aabb.ccdd.eeff)"
	reIfAddr = regexp.MustCompile(`(?i)address is\s+([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})`)
)

// ParseCLIIfMacs interpreta "show interfaces" in modo stateful: la riga di
// intestazione fissa l'interfaccia corrente, la successiva "address is <mac>"
// emette la coppia.
//
// Si parsa l'output completo di proposito: un filtro "| include address is"
// perderebbe il nome dell'interfaccia.
func ParseCLIIfMacs(text string) []IfMac {
	var out []IfMac
	cur := ""
	for _, line := range strings.Split(text, "\n") {
		if h := reIfHdr.FindStringSubmatch(line); h != nil {
			cur = h[1]
		}
		if a := reIfAddr.FindStringSubmatch(line); a != nil && cur != "" {
			out = append(out, IfMac{Interface: cur, Mac: a[1]})
		}
	}
	return out
}
