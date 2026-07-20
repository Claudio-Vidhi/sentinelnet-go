// Package driver: astrazione per-vendor dei comandi CLI (versione, backup, ARP).
// Porta di drivers/*.py + DRIVER_REGISTRY/VENDOR_DRIVER_DEFAULTS di core/core_engine.py.
//
// Le regex sono replicate alla lettera dai driver Python: NON vanno "migliorate",
// sono state ricavate da output reale di firmware specifici e una modifica fa
// regredire il rilevamento versione a "Unknown" senza errori visibili.
package driver

import "strings"

// Runner è la porzione di sessione CLI usata dai driver. Volutamente minimale:
// evita che questo package importi internal/collect (che a sua volta importa
// questo package in triage.go) creando un ciclo. *collect.Session la soddisfa.
type Runner interface {
	Run(cmd string) string
}

type Driver interface {
	// GetVersion esegue il comando di versione e ne estrae la versione,
	// oppure "Unknown" se il pattern non corrisponde.
	GetVersion(r Runner) string
	// BackupCommand è il comando la cui uscita costituisce il backup.
	BackupCommand() string
	// ARPCommand è il comando per la tabella ARP.
	ARPCommand() string
}

// registry: nome-driver → implementazione. Corrisponde a DRIVER_REGISTRY.
// cisco_9800 (Catalyst 9800, IOS-XE) usa gli stessi comandi di cisco_ios,
// esattamente come nel Python.
var registry = map[string]Driver{
	"cisco_ios":      CiscoIOS{},
	"cisco_s300":     CiscoCBS{},
	"hp_procurve":    HPProcurve{},
	"juniper_junos":  JuniperJunos{},
	"aruba_os":       ArubaOS{},
	"fortinet":       Fortinet{},
	"paloalto_panos": PaloAlto{},
	"cisco_wlc":      CiscoWLC{},
	"cisco_9800":     CiscoIOS{},
}

// vendorDefaults: fallback nome-vendor → nome-driver, usato quando il registro
// vendor non specifica un driver. Corrisponde a VENDOR_DRIVER_DEFAULTS.
var vendorDefaults = map[string]string{
	"cisco":      "cisco_ios",
	"cisco_cbs":  "cisco_s300",
	"hpe":        "hp_procurve",
	"hp":         "hp_procurve",
	"juniper":    "juniper_junos",
	"aruba":      "aruba_os",
	"fortinet":   "fortinet",
	"paloalto":   "paloalto_panos",
	"cisco_wlc":  "cisco_wlc",
	"cisco_9800": "cisco_9800",
}

// Resolve risolve un vendor nel driver corrispondente, con lo stesso ordine del
// Python: prima il campo 'driver' del registro vendor, poi il fallback per nome
// vendor. driverName può essere "" quando il registro non lo specifica.
func Resolve(vendor, driverName string) (Driver, bool) {
	if driverName == "" {
		driverName = vendorDefaults[normalize(vendor)]
	}
	d, ok := registry[driverName]
	return d, ok
}

// ResolveOrDefault è come Resolve ma ricade su cisco_ios per i vendor non
// riconosciuti, preservando il comportamento storico del port Go (che inviava
// comandi IOS a qualsiasi apparato).
func ResolveOrDefault(vendor, driverName string) Driver {
	if d, ok := Resolve(vendor, driverName); ok {
		return d
	}
	return CiscoIOS{}
}

// IsFortinet indica i vendor gestiti via REST (fortigate_service) e non via SSH:
// vanno intercettati prima del percorso SSH/triage.
func IsFortinet(vendor string) bool {
	switch normalize(vendor) {
	case "fortinet", "fortigate", "fortiwifi", "fortios":
		return true
	}
	return false
}

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
