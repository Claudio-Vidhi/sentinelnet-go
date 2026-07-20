package fortigate

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// route accoppia un frammento di path al corpo da restituire. È una slice e
// non una mappa perché l'ordine conta: la prima regola che combacia vince, e
// l'iterazione di una mappa Go è deliberatamente casuale.
type route struct{ frag, body string }

// okAll risponde a qualunque endpoint con una lista vuota.
var okAll = route{"", `{"results":[]}`}

// diagnoseServer serve la prima regola che combacia col path. Un corpo vuoto
// risponde 500, ed è il modo per far fallire una sola sezione: un corpo non
// JSON non basterebbe, perché il client lo incapsula in {"raw": ...}.
func diagnoseServer(t *testing.T, routes ...route) *Client {
	t.Helper()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		for _, rt := range routes {
			if !strings.Contains(r.URL.Path, rt.frag) {
				continue
			}
			if rt.body == "" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Write([]byte(rt.body))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	return c
}

// Un client indicato per IP non richiede risoluzione e raccoglie tutte le
// sezioni, policy_lookup inclusa quando è indicata una destinazione.
func TestDiagnoseClientByIP(t *testing.T) {
	c := diagnoseServer(t, okAll)
	res := c.DiagnoseClient(context.Background(), DiagnoseParams{
		Client: "10.0.0.5", Dest: "8.8.8.8", DestPort: 443, Protocol: "TCP",
	}, nil)

	if res.ClientType != "ip" {
		t.Errorf("client_type = %q, atteso ip", res.ClientType)
	}
	if res.ResolvedIP != nil {
		t.Error("resolved_ip non deve comparire per un client già IP")
	}
	for _, name := range []string{"device_inventory", "arp", "dhcp_leases",
		"sessions", "traffic_logs", "policy_lookup", "wifi_clients"} {
		if _, ok := res.Sections[name]; !ok {
			t.Errorf("sezione %q mancante", name)
		}
	}
}

// Senza destinazione il policy lookup non ha senso e va omesso.
func TestDiagnoseClientSkipsPolicyLookupWithoutDest(t *testing.T) {
	c := diagnoseServer(t, okAll)
	res := c.DiagnoseClient(context.Background(), DiagnoseParams{Client: "10.0.0.5"}, nil)
	if _, ok := res.Sections["policy_lookup"]; ok {
		t.Error("policy_lookup presente senza destinazione")
	}
}

// Un MAC va risolto in IP dalle sezioni già raccolte, altrimenti sessioni,
// log e policy lookup non avrebbero su cosa filtrare.
func TestDiagnoseClientResolvesMACToIP(t *testing.T) {
	c := diagnoseServer(t,
		route{"user/device/query", `{"results":[{"mac":"AA-BB-CC-DD-EE-FF","ip":"10.0.0.7"}]}`},
		okAll)
	res := c.DiagnoseClient(context.Background(), DiagnoseParams{Client: "aa:bb:cc:dd:ee:ff"}, nil)

	if res.ClientType != "mac" {
		t.Errorf("client_type = %q, atteso mac", res.ClientType)
	}
	if res.ResolvedIP == nil || *res.ResolvedIP != "10.0.0.7" {
		t.Fatalf("resolved_ip = %v, atteso 10.0.0.7", res.ResolvedIP)
	}
	if _, ok := res.Sections["sessions"]; !ok {
		t.Error("sessioni non raccolte dopo la risoluzione del MAC")
	}
}

// MAC non risolvibile: resolved_ip resta presente ma vuoto e le sezioni che
// dipendono dall'IP vengono saltate invece di essere interrogate a vuoto.
func TestDiagnoseClientUnresolvedMACSkipsIPSections(t *testing.T) {
	c := diagnoseServer(t, okAll)
	res := c.DiagnoseClient(context.Background(), DiagnoseParams{
		Client: "aa:bb:cc:dd:ee:ff", Dest: "8.8.8.8",
	}, nil)

	if res.ResolvedIP == nil || *res.ResolvedIP != "" {
		t.Errorf("resolved_ip = %v, atteso presente e vuoto", res.ResolvedIP)
	}
	for _, name := range []string{"sessions", "traffic_logs", "policy_lookup"} {
		if _, ok := res.Sections[name]; ok {
			t.Errorf("sezione %q raccolta senza un IP su cui filtrare", name)
		}
	}
	if _, ok := res.Sections["wifi_clients"]; !ok {
		t.Error("wifi_clients va raccolta comunque")
	}
}

// Il punto della diagnosi: una fonte che cede non deve farne fallire l'intera
// raccolta, ma comparire come errore nella sua sezione.
func TestDiagnoseClientSectionErrorIsIsolated(t *testing.T) {
	// Il solo endpoint DHCP fallisce (500).
	c := diagnoseServer(t, route{"system/dhcp", ``}, okAll)
	res := c.DiagnoseClient(context.Background(), DiagnoseParams{Client: "10.0.0.5"}, nil)

	sec, ok := res.Sections["dhcp_leases"].(map[string]string)
	if !ok || sec["error"] == "" {
		t.Fatalf("dhcp_leases = %#v, attesa una sezione con errore", res.Sections["dhcp_leases"])
	}
	if _, ok := res.Sections["arp"].(Result); !ok {
		t.Error("una sezione fallita ha compromesso le altre")
	}
}

// L'output CLI del ripiego SSH è una stringa, non una lista di voci: la
// risoluzione del MAC deve ignorarlo senza andare in panic.
func TestResolveMACIgnoresCLIOutput(t *testing.T) {
	sections := map[string]any{
		"device_inventory": Result{Source: "ssh", Data: "aa:bb:cc:dd:ee:ff 10.0.0.7"},
		"arp":              Result{Source: "api", Data: []any{"non-una-mappa"}},
		"dhcp_leases":      map[string]string{"error": "boom"},
	}
	if got := resolveMAC("aa:bb:cc:dd:ee:ff", sections); got != "" {
		t.Errorf("resolveMAC = %q, atteso vuoto", got)
	}
}

// Le notazioni MAC diverse devono confrontarsi fra loro: l'inventario di un
// FortiGate e l'input dell'operatore raramente usano la stessa.
func TestResolveMACNormalizesNotation(t *testing.T) {
	sections := map[string]any{
		"device_inventory": Result{Data: []any{
			map[string]any{"mac": "aabb.ccdd.eeff", "ip": "10.0.0.9"},
		}},
	}
	if got := resolveMAC("AA-BB-CC-DD-EE-FF", sections); got != "10.0.0.9" {
		t.Errorf("resolveMAC = %q, atteso 10.0.0.9", got)
	}
}

// Una voce che combacia ma senza IP non va accettata: si continua a cercare
// nelle fonti successive.
func TestResolveMACSkipsEntryWithoutIP(t *testing.T) {
	sections := map[string]any{
		"device_inventory": Result{Data: []any{
			map[string]any{"mac": "aa:bb:cc:dd:ee:ff"},
		}},
		"arp": Result{Data: []any{
			map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.11"},
		}},
	}
	if got := resolveMAC("aa:bb:cc:dd:ee:ff", sections); got != "10.0.0.11" {
		t.Errorf("resolveMAC = %q, atteso il fallback su arp", got)
	}
}

func TestIsMACRecognisesNotations(t *testing.T) {
	for _, s := range []string{"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF",
		"aabb.ccdd.eeff", "aabbccddeeff"} {
		if !reMACClient.MatchString(s) {
			t.Errorf("%q non riconosciuto come MAC", s)
		}
	}
	for _, s := range []string{"10.0.0.5", "", "aa:bb:cc:dd:ee", "host.local"} {
		if reMACClient.MatchString(s) {
			t.Errorf("%q riconosciuto come MAC per errore", s)
		}
	}
}
