package observability

import (
	"testing"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestExtractEndpoints(t *testing.T) {
	// FortiGate: coppie key=value.
	src, dst, port := extractEndpoints(`action="blocked" srcip=10.0.0.5 dstip=8.8.8.8 dstport=443`)
	if src != "10.0.0.5" || dst != "8.8.8.8" || port == nil || *port != 443 {
		t.Errorf("kv: src=%q dst=%q port=%v", src, dst, port)
	}
	// Le virgolette sono ammesse.
	src, dst, _ = extractEndpoints(`srcip="10.0.0.5" dstip="8.8.8.8"`)
	if src != "10.0.0.5" || dst != "8.8.8.8" {
		t.Errorf("kv con virgolette: src=%q dst=%q", src, dst)
	}
	// Formato generico: prime due IP distinte.
	src, dst, port = extractEndpoints("deny 192.168.1.10 -> 192.168.1.20 su porta 80")
	if src != "192.168.1.10" || dst != "192.168.1.20" || port != nil {
		t.Errorf("generico: src=%q dst=%q port=%v", src, dst, port)
	}
	// IP ripetuti: la seconda distinta è la destinazione.
	src, dst, _ = extractEndpoints("10.0.0.1 10.0.0.1 10.0.0.2")
	if src != "10.0.0.1" || dst != "10.0.0.2" {
		t.Errorf("ip ripetuti: src=%q dst=%q", src, dst)
	}
	// Una sola IP: nessun endpoint utilizzabile.
	if s, d, _ := extractEndpoints("qualcosa su 10.0.0.1"); s != "" || d != "" {
		t.Errorf("una sola ip: src=%q dst=%q, attesi vuoti", s, d)
	}
	if s, d, _ := extractEndpoints(""); s != "" || d != "" {
		t.Errorf("messaggio vuoto: src=%q dst=%q", s, d)
	}
}

// Precisione prima del richiamo: un'azione di sicurezza a severità bassa senza
// flusso corroborante NON deve produrre un evento.
func TestCorrelateRequiresFlowEvidence(t *testing.T) {
	m, obs, _ := testManager(t)
	now := time.Now().Unix()

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "T", "10.0.0.9", 5, "blocked",
		`action="blocked" srcip=10.0.0.5 dstip=8.8.8.8 dstport=443`)
	obs.Sync()

	n, err := m.CorrelateOnce(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("eventi emessi = %d, attesi 0 senza flusso corroborante", n)
	}
}

// Con il flusso corroborante l'evento viene emesso.
func TestCorrelateEmitsWithFlowEvidence(t *testing.T) {
	m, obs, _ := testManager(t)
	now := time.Now().Unix()
	bucket := (now - 60) - (now-60)%60

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "T", "10.0.0.9", 5, "blocked",
		`action="blocked" srcip=10.0.0.5 dstip=8.8.8.8 dstport=443`)
	obs.EnqueueWrite(`INSERT INTO flow_aggregates
		(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
		VALUES (?,?,?,?,?,?,?,?,1)`, bucket, "T", "10.0.0.5", "8.8.8.8", 6, 443, 1200, 8)
	obs.Sync()

	n, err := m.CorrelateOnce(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("eventi emessi = %d, atteso 1", n)
	}
	obs.Sync()

	var kind, srcIP, status, evidence string
	if err := obs.DB.QueryRow(`SELECT kind, src_ip, status, evidence_json
		FROM correlated_events`).Scan(&kind, &srcIP, &status, &evidence); err != nil {
		t.Fatal(err)
	}
	if kind != "traffico_bloccato_medio" {
		t.Errorf("kind = %q", kind)
	}
	if srcIP != "10.0.0.5" || status != "new" {
		t.Errorf("src=%q status=%q", srcIP, status)
	}
	if evidence == "" || evidence == "{}" {
		t.Errorf("evidence_json = %q", evidence)
	}
}

// Alta severità: emerge anche senza flusso corroborante.
func TestCorrelateEmitsHighSeverityWithoutFlow(t *testing.T) {
	m, obs, _ := testManager(t)
	now := time.Now().Unix()

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "T", "10.0.0.9", 2, "", "guasto critico sull'apparato")
	obs.Sync()

	n, err := m.CorrelateOnce(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("eventi emessi = %d, atteso 1 per alta severità", n)
	}
	obs.Sync()
	var kind string
	obs.DB.QueryRow(`SELECT kind FROM correlated_events`).Scan(&kind)
	if kind != "syslog_critico" {
		t.Errorf("kind = %q, atteso syslog_critico", kind)
	}
}

// Rieseguire la correlazione non deve duplicare: la dedup_key è deterministica
// e l'INSERT è OR IGNORE.
func TestCorrelateIsIdempotent(t *testing.T) {
	m, obs, _ := testManager(t)
	now := time.Now().Unix()

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "T", "10.0.0.9", 2, "", "guasto critico")
	obs.Sync()

	for i := 0; i < 3; i++ {
		if _, err := m.CorrelateOnce(now); err != nil {
			t.Fatal(err)
		}
		obs.Sync()
	}
	var n int
	obs.DB.QueryRow(`SELECT COUNT(*) FROM correlated_events`).Scan(&n)
	if n != 1 {
		t.Errorf("righe = %d, attesa 1: la deduplicazione non ha funzionato", n)
	}
}

// Un flusso di un ALTRO tenant non deve corroborare l'evento.
func TestCorrelateNeverMatchesAcrossTenants(t *testing.T) {
	m, obs, _ := testManager(t)
	now := time.Now().Unix()
	bucket := (now - 60) - (now-60)%60

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "TenantA", "10.0.0.9", 5, "blocked",
		`action="blocked" srcip=10.0.0.5 dstip=8.8.8.8`)
	// Stesso flusso, ma di TenantB.
	obs.EnqueueWrite(`INSERT INTO flow_aggregates
		(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
		VALUES (?,?,?,?,?,?,?,?,1)`, bucket, "TenantB", "10.0.0.5", "8.8.8.8", 6, 443, 1200, 8)
	obs.Sync()

	n, err := m.CorrelateOnce(now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("eventi emessi = %d, attesi 0: un flusso di un altro tenant non deve corroborare", n)
	}
}

// La posizione fisica arriva dalla Client Map, vincolata al tenant.
func TestCorrelateEnrichesWithSwitchPort(t *testing.T) {
	m, obs, st := testManager(t)
	now := time.Now().Unix()
	bucket := (now - 60) - (now-60)%60

	if _, err := st.RecordARPEntries(
		[]store.ARPInput{{MAC: "aa:bb:cc:dd:ee:05", IP: "10.0.0.5"}},
		"10.0.0.1", "GW", "switch", "T", ""); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSighting(&store.MacSighting{
		Mac: "aa:bb:cc:dd:ee:05", SwitchIP: "10.1.1.1", SwitchName: "SW-ACCESSO",
		Interface: "Gi1/0/7", Vlan: "10", Tenant: "T",
	}); err != nil {
		t.Fatal(err)
	}

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "T", "10.0.0.9", 5, "blocked",
		`action="blocked" srcip=10.0.0.5 dstip=8.8.8.8`)
	obs.EnqueueWrite(`INSERT INTO flow_aggregates
		(window_start, tenant, src_ip, dst_ip, protocol, dst_port, total_bytes, total_packets, flow_count)
		VALUES (?,?,?,?,?,?,?,?,1)`, bucket, "T", "10.0.0.5", "8.8.8.8", 6, 443, 1200, 8)
	obs.Sync()

	if _, err := m.CorrelateOnce(now); err != nil {
		t.Fatal(err)
	}
	obs.Sync()

	var switchPort string
	if err := obs.DB.QueryRow(`SELECT COALESCE(switch_port,'') FROM correlated_events`).Scan(&switchPort); err != nil {
		t.Fatal(err)
	}
	if switchPort != "SW-ACCESSO:Gi1/0/7" {
		t.Errorf("switch_port = %q, atteso SW-ACCESSO:Gi1/0/7", switchPort)
	}
}

// Eventi non di sicurezza e a bassa severità non sono nemmeno candidati.
func TestCorrelateIgnoresIrrelevantEvents(t *testing.T) {
	m, obs, _ := testManager(t)
	now := time.Now().Unix()

	obs.EnqueueWrite(`INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message)
		VALUES (?,?,?,?,?,?)`, now-60, "T", "10.0.0.9", 6, "allow", "traffico consentito 1.1.1.1 2.2.2.2")
	obs.Sync()

	if n, err := m.CorrelateOnce(now); err != nil || n != 0 {
		t.Errorf("eventi emessi = %d (err %v), attesi 0", n, err)
	}
}
