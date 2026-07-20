package fortigate

import (
	"context"
	"regexp"
	"strings"
)

// DiagnoseParams sono i parametri della diagnosi aggregata di un client.
// Client è un IP oppure un MAC; Dest (opzionale) abilita il policy lookup.
type DiagnoseParams struct {
	Client   string
	Dest     string
	DestPort int
	Protocol string
}

// DiagnoseResult raccoglie in un colpo solo tutto ciò che il FortiGate sa di
// un client. Sections mappa il nome della sezione al suo contenuto: una
// Result se la sorgente ha risposto, oppure {"error": "..."} se ha fallito.
type DiagnoseResult struct {
	Client     string         `json:"client"`
	ClientType string         `json:"client_type"`
	FortiGate  string         `json:"fortigate"`
	ResolvedIP *string        `json:"resolved_ip,omitempty"`
	Sections   map[string]any `json:"sections"`
}

var (
	reMACClient = regexp.MustCompile(`^[0-9a-fA-F]{2}([:\-.]?[0-9a-fA-F]{2}){5}$`)
	reNonHex    = regexp.MustCompile(`[^0-9a-f]`)
)

// DiagnoseClient interroga in sequenza le fonti del FortiGate che riguardano
// un client — inventario device, ARP, DHCP, sessioni, policy match, ultimi
// log e client wifi — e le impacchetta in un unico risultato.
//
// Ogni sezione è best-effort: se una fonte fallisce l'errore finisce nella
// sezione e la diagnosi prosegue. Una diagnosi parziale è utile, mentre un
// 502 perché il solo DHCP non risponde non lo sarebbe.
//
// Le chiamate restano sequenziali anche se molte sono indipendenti: il
// ripiego SSH apre una sessione per comando, e aprirne quattro in parallelo
// verso lo stesso apparato è un modo affidabile per farsi rifiutare.
func (c *Client) DiagnoseClient(ctx context.Context, p DiagnoseParams, ssh SSHRunner) DiagnoseResult {
	isMAC := reMACClient.MatchString(p.Client)
	res := DiagnoseResult{
		Client:    p.Client,
		FortiGate: c.IP,
		Sections:  map[string]any{},
	}
	res.ClientType = "ip"
	if isMAC {
		res.ClientType = "mac"
	}

	// section esegue fn e ne archivia l'esito, trasformando l'errore in dato
	// invece di propagarlo.
	section := func(name string, fn func() (Result, error)) {
		r, err := fn()
		if err != nil {
			res.Sections[name] = map[string]string{"error": err.Error()}
			return
		}
		res.Sections[name] = r
	}

	section("device_inventory", func() (Result, error) { return c.DeviceInventory(ctx, ssh) })
	section("arp", func() (Result, error) { return c.ARPTable(ctx, ssh) })
	section("dhcp_leases", func() (Result, error) { return c.DHCPLeases(ctx, ssh) })

	clientIP := ""
	if !isMAC {
		clientIP = p.Client
	} else {
		// Sessioni, log e policy lookup ragionano per IP: se il client è
		// arrivato come MAC va prima risolto con quanto appena raccolto.
		clientIP = resolveMAC(p.Client, res.Sections)
		ip := clientIP
		res.ResolvedIP = &ip
	}

	if clientIP != "" {
		section("sessions", func() (Result, error) {
			return c.Sessions(ctx, clientIP, "", 0, 100, ssh)
		})
		section("traffic_logs", func() (Result, error) {
			r, _, err := c.TrafficLogs(ctx, clientIP, "", "", 50, "disk", ssh)
			return r, err
		})
		if p.Dest != "" {
			section("policy_lookup", func() (Result, error) {
				return c.PolicyLookup(ctx, clientIP, p.Dest, p.Protocol, p.DestPort, "")
			})
		}
	}
	section("wifi_clients", func() (Result, error) { return c.WifiClients(ctx, ssh) })
	return res
}

// resolveMAC cerca l'IP corrispondente a un MAC nelle sezioni già raccolte.
// L'ordine non è casuale: l'inventario device è la fonte più ricca, il DHCP
// dà il lease corrente, l'ARP è l'ultima spiaggia perché una voce può essere
// scaduta ma ancora in tabella.
//
// Le sezioni ottenute via SSH contengono l'output CLI grezzo (una stringa,
// non una lista) e vengono ignorate: non c'è un parser CLI per queste tabelle.
func resolveMAC(macClient string, sections map[string]any) string {
	want := normHex(macClient)
	for _, name := range []string{"device_inventory", "dhcp_leases", "arp"} {
		r, ok := sections[name].(Result)
		if !ok {
			continue
		}
		rows, ok := r.Data.([]any)
		if !ok {
			continue
		}
		for _, row := range rows {
			entry, ok := row.(map[string]any)
			if !ok {
				continue
			}
			mac, _ := entry["mac"].(string)
			if normHex(mac) != want {
				continue
			}
			if ip, _ := entry["ip"].(string); ip != "" {
				return ip
			}
		}
	}
	return ""
}

// normHex riduce un MAC ai soli caratteri esadecimali minuscoli, così le
// notazioni diverse (":", "-", ".", nessun separatore) si confrontano fra loro.
func normHex(s string) string {
	return reNonHex.ReplaceAllString(strings.ToLower(s), "")
}
