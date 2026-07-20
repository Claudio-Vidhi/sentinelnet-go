package fortigate

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// Il caso normale: la REST risponde e l'SSH non viene nemmeno tentato.
func TestApiOrSSHPrefersREST(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":[{"name":"port1"}]}`))
	})
	sshCalled := false
	ssh := func(ctx context.Context, cmd string) (string, error) {
		sshCalled = true
		return "", nil
	}

	res, err := c.Interfaces(context.Background(), ssh)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "api" {
		t.Errorf("source = %q, atteso api", res.Source)
	}
	if sshCalled {
		t.Error("l'SSH non doveva essere tentato con la REST funzionante")
	}
	if res.APIError != "" {
		t.Errorf("api_error = %q, atteso vuoto", res.APIError)
	}
}

// Se la REST fallisce si ricade sull'SSH, conservando il motivo del primo
// fallimento: serve a capire perché l'integrazione REST non funziona.
func TestApiOrSSHFallsBackAndKeepsAPIError(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	ssh := func(ctx context.Context, cmd string) (string, error) {
		return "uscita CLI", nil
	}

	res, err := c.ARPTable(context.Background(), ssh)
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "ssh" || res.Data != "uscita CLI" {
		t.Errorf("risultato = %+v", res)
	}
	if !strings.Contains(res.APIError, "401") {
		t.Errorf("api_error = %q, atteso contenesse il motivo REST", res.APIError)
	}
}

// Se falliscono entrambi l'errore deve riportare tutti e due i motivi.
func TestApiOrSSHReportsBothFailures(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	ssh := func(ctx context.Context, cmd string) (string, error) {
		return "", errors.New("connessione rifiutata")
	}

	_, err := c.ARPTable(context.Background(), ssh)
	if err == nil {
		t.Fatal("atteso errore")
	}
	msg := err.Error()
	if !strings.Contains(msg, "API:") || !strings.Contains(msg, "SSH:") {
		t.Errorf("messaggio = %q, attesi entrambi i motivi", msg)
	}
	if !strings.Contains(msg, "connessione rifiutata") {
		t.Errorf("messaggio senza il motivo SSH: %q", msg)
	}
}

// Senza ripiego SSH l'errore REST viene propagato tale e quale.
func TestApiOrSSHWithoutFallback(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	if _, err := c.ARPTable(context.Background(), nil); err == nil {
		t.Fatal("atteso errore senza ripiego")
	}
}

// monitor/system/status ha version e serial FUORI da "results": vanno fusi,
// altrimenti la UI mostra un FortiGate senza versione.
func TestSystemStatusMergesEnvelopeFields(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"results":{"hostname":"FGT-60F"},"version":"v7.2.5","serial":"FGT60F123"}`))
	})
	res, err := c.SystemStatus(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	if data["hostname"] != "FGT-60F" {
		t.Errorf("hostname = %v", data["hostname"])
	}
	if data["version"] != "7.2.5" {
		t.Errorf("version = %v, attesa 7.2.5 senza la v", data["version"])
	}
	if data["serial"] != "FGT60F123" {
		t.Errorf("serial = %v", data["serial"])
	}
}

// Il ripiego SSH di system status parsa l'output invece di restituirlo grezzo.
func TestSystemStatusParsesCLIFallback(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	cli := "Version: FortiGate-60F v7.2.5,build1517,230410 (GA.F)\n" +
		"Serial-Number: FGT60FTK1234\n" +
		"Hostname: FGT-SEDE\n"
	res, err := c.SystemStatus(context.Background(), func(context.Context, string) (string, error) {
		return cli, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data := res.Data.(map[string]any)
	if data["hostname"] != "FGT-SEDE" {
		t.Errorf("hostname = %v", data["hostname"])
	}
	if data["version"] != "7.2.5" {
		t.Errorf("version = %v", data["version"])
	}
	if data["model"] != "FortiGate-60F" {
		t.Errorf("model = %v", data["model"])
	}
	if data["serial"] != "FGT60FTK1234" {
		t.Errorf("serial = %v", data["serial"])
	}
	if !strings.Contains(data["raw"].(string), "build1517") {
		t.Error("testo grezzo non conservato")
	}
}

// I modelli senza disco falliscono su log/disk: si deve ripiegare su memory.
func TestTrafficLogsFallsBackToMemory(t *testing.T) {
	var paths []string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "/disk/") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"results":[{"srcip":"10.0.0.5"}]}`))
	})

	res, dev, err := c.TrafficLogs(context.Background(), "10.0.0.5", "", "deny", 10, "disk")
	if err != nil {
		t.Fatal(err)
	}
	if dev != "memory" {
		t.Errorf("log device = %q, atteso memory", dev)
	}
	if len(paths) != 2 || !strings.Contains(paths[0], "disk") {
		t.Errorf("percorsi tentati = %v, atteso prima disk poi memory", paths)
	}
	if res.Source != "api" {
		t.Errorf("source = %q", res.Source)
	}
}

func TestTrafficLogsBuildsFilter(t *testing.T) {
	var filter, rows string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		filter, rows = r.URL.Query().Get("filter"), r.URL.Query().Get("rows")
		w.Write([]byte(`{"results":[]}`))
	})
	if _, _, err := c.TrafficLogs(context.Background(), "10.0.0.5", "8.8.8.8", "deny", 25, "memory"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"srcip==10.0.0.5", "dstip==8.8.8.8", "action==deny"} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter = %q, atteso contenesse %q", filter, want)
		}
	}
	if rows != "25" {
		t.Errorf("rows = %q", rows)
	}
}

// Gli endpoint cmdb chiedono solo i campi usati dalla UI.
func TestRESTOnlyEndpointsUseFieldProjection(t *testing.T) {
	var format string
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		format = r.URL.Query().Get("format")
		w.Write([]byte(`{"results":[]}`))
	})
	if _, err := c.FirewallAddresses(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(format, "name") || !strings.Contains(format, "subnet") {
		t.Errorf("format = %q", format)
	}
}

func TestSessionsBuildsParams(t *testing.T) {
	var q url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		w.Write([]byte(`{"results":[]}`))
	})
	if _, err := c.Sessions(context.Background(), "10.0.0.5", "8.8.8.8", 443, 100, nil); err != nil {
		t.Fatal(err)
	}
	if q.Get("srcaddr") != "10.0.0.5" || q.Get("dstaddr") != "8.8.8.8" ||
		q.Get("dport") != "443" || q.Get("count") != "100" {
		t.Errorf("parametri = %v", q)
	}
}

func TestPolicyLookupParams(t *testing.T) {
	var q url.Values
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.Query()
		w.Write([]byte(`{"results":{"policyid":7}}`))
	})
	res, err := c.PolicyLookup(context.Background(), "10.0.0.5", "8.8.8.8", "TCP", 443, "port1")
	if err != nil {
		t.Fatal(err)
	}
	if q.Get("sourceip") != "10.0.0.5" || q.Get("dest") != "8.8.8.8" ||
		q.Get("protocol") != "TCP" || q.Get("destport") != "443" || q.Get("srcintf") != "port1" {
		t.Errorf("parametri = %v", q)
	}
	if data := res.Data.(map[string]any); data["policyid"] != float64(7) {
		t.Errorf("data = %v", res.Data)
	}
}

// unwrapResults deve restituire l'intera risposta quando "results" manca.
func TestUnwrapResults(t *testing.T) {
	if got := unwrapResults(map[string]any{"results": 42}); got != 42 {
		t.Errorf("con results = %v", got)
	}
	full := map[string]any{"altro": 1}
	if got := unwrapResults(full); got.(map[string]any)["altro"] != 1 {
		t.Errorf("senza results = %v", got)
	}
}
