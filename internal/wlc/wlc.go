// Package wlc: osservabilità wireless per controller Cisco — AireOS
// (2504/3504/5508/8540, vWLC) e Catalyst 9800 (IOS-XE).
//
// Le due famiglie hanno CLI diverse: Commands traduce ogni servizio nel
// comando giusto per piattaforma. L'output resta testo grezzo, pensato per
// essere interpretato da un LLM (MCP / assistente AI) più che dalla UI.
//
// Il package è puro: non apre connessioni. Il trasporto SSH è iniettato dal
// chiamante come Runner, così la logica di piattaforma è testabile senza rete.
package wlc

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Platform distingue le due famiglie di controller.
type Platform string

const (
	AireOS Platform = "aireos"
	IOSXE  Platform = "iosxe"
)

// PlatformOf deduce la piattaforma dal vendor. Il vendor 'cisco' generico è
// trattato come 9800/IOS-XE: è il caso più probabile su un impianto recente.
func PlatformOf(vendor string) Platform {
	if strings.ToLower(strings.TrimSpace(vendor)) == "cisco_wlc" {
		return AireOS
	}
	return IOSXE
}

// Vendors sono i vendor di inventario ammessi su queste rotte.
var Vendors = []string{"cisco_wlc", "cisco_9800", "cisco"}

// IsWLCVendor indica se il vendor è un controller wireless gestibile.
func IsWLCVendor(vendor string) bool {
	v := strings.ToLower(strings.TrimSpace(vendor))
	for _, w := range Vendors {
		if v == w {
			return true
		}
	}
	return false
}

// PagingCommand disabilita la paginazione dell'output.
//
// Non è un dettaglio cosmetico: senza, un "show client summary" su un
// controller carico si ferma al primo "--More--" e restituisce solo la prima
// schermata. AireOS non conosce "terminal length 0", che è la ragione per cui
// il comando non può essere quello usato per gli switch.
func (p Platform) PagingCommand() string {
	if p == AireOS {
		return "config paging disable"
	}
	return "terminal length 0"
}

// Commands mappa servizio -> piattaforma -> comando. {mac} è sostituito nei
// comandi per-client.
var Commands = map[string]map[Platform]string{
	"status": {
		AireOS: "show sysinfo",
		IOSXE:  "show wireless summary",
	},
	"ap_summary": {
		AireOS: "show ap summary",
		IOSXE:  "show ap summary",
	},
	"client_summary": {
		AireOS: "show client summary",
		IOSXE:  "show wireless client summary",
	},
	"client_detail": {
		AireOS: "show client detail {mac}",
		IOSXE:  "show wireless client mac-address {mac} detail",
	},
	"wlan_summary": {
		AireOS: "show wlan summary",
		IOSXE:  "show wlan summary",
	},
	"rogue_aps": {
		AireOS: "show rogue ap summary",
		IOSXE:  "show wireless wps rogue ap summary",
	},
	"interfaces": {
		AireOS: "show interface summary",
		IOSXE:  "show ip interface brief",
	},
}

// Result è la risposta di un servizio: la piattaforma riconosciuta, il
// comando effettivamente eseguito e il suo output grezzo.
type Result struct {
	Platform string `json:"platform"`
	Command  string `json:"command"`
	Data     string `json:"data"`
}

// Runner esegue un comando show sul controller e ne ritorna l'output. Riceve
// la piattaforma perché il trasporto deve disabilitare la paginazione con il
// comando giusto.
type Runner func(ctx context.Context, p Platform, command string) (string, error)

// reMAC accetta le notazioni comuni: due cifre esadecimali seguite da altre
// cinque coppie, con separatore ":", "-", "." o assente.
var reMAC = regexp.MustCompile(`^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$`)

var reNonHex = regexp.MustCompile(`[^0-9a-f]`)

// NormalizeMAC porta un MAC nel formato aa:bb:cc:dd:ee:ff, accettato da
// entrambe le piattaforme, e segnala l'input non valido.
//
// Non usa internal/mac.NormalizeMac perché quella ritorna l'input invariato
// quando non è un MAC (divergenza §5): qui un MAC malformato deve fermarsi
// prima di finire in una riga di comando.
func NormalizeMAC(mac string) (string, error) {
	trimmed := strings.ReplaceAll(strings.TrimSpace(mac), " ", "")
	if !reMAC.MatchString(trimmed) {
		return "", fmt.Errorf("MAC address non valido: '%s'", mac)
	}
	d := reNonHex.ReplaceAllString(strings.ToLower(trimmed), "")
	parts := make([]string, 0, 6)
	for i := 0; i < 12; i += 2 {
		parts = append(parts, d[i:i+2])
	}
	return strings.Join(parts, ":"), nil
}

// Query esegue il servizio richiesto sul controller.
func Query(ctx context.Context, run Runner, vendor, service, mac string) (Result, error) {
	byPlatform, ok := Commands[service]
	if !ok {
		return Result{}, fmt.Errorf("servizio WLC sconosciuto: '%s'", service)
	}
	p := PlatformOf(vendor)
	command := byPlatform[p]

	if strings.Contains(command, "{mac}") {
		if mac == "" {
			return Result{}, fmt.Errorf("il servizio '%s' richiede un MAC address", service)
		}
		norm, err := NormalizeMAC(mac)
		if err != nil {
			return Result{}, err
		}
		command = strings.ReplaceAll(command, "{mac}", norm)
	}

	data, err := run(ctx, p, command)
	if err != nil {
		return Result{}, err
	}
	return Result{Platform: string(p), Command: command, Data: data}, nil
}

// Diagnosis è la diagnosi aggregata di un client wireless.
type Diagnosis struct {
	WLC       string         `json:"wlc"`
	ClientMAC string         `json:"client_mac"`
	Platform  string         `json:"platform"`
	Sections  map[string]any `json:"sections"`
}

// DiagnoseWifiClient raccoglie dettaglio client, stato AP, WLAN e rogue AP
// vicini. Come per il FortiGate ogni sezione è best-effort: l'errore finisce
// nella sezione e la diagnosi prosegue.
func DiagnoseWifiClient(ctx context.Context, run Runner, ip, vendor, mac string) Diagnosis {
	d := Diagnosis{
		WLC:       ip,
		ClientMAC: mac,
		Platform:  string(PlatformOf(vendor)),
		Sections:  map[string]any{},
	}
	for _, svc := range []string{"client_detail", "ap_summary", "wlan_summary", "rogue_aps"} {
		arg := ""
		if svc == "client_detail" {
			arg = mac
		}
		res, err := Query(ctx, run, vendor, svc, arg)
		if err != nil {
			d.Sections[svc] = map[string]string{"error": err.Error()}
			continue
		}
		d.Sections[svc] = res
	}
	return d
}
