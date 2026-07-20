package observability

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
)

// Parametri della correlazione, allineati al Python.
const (
	CorrelationInterval = 300 * time.Second // un ciclo ogni 5 minuti
	correlationLookback = 900               // eventi syslog degli ultimi 15 minuti
	matchDeltaS         = 120               // ±120s fra evento e bucket di flusso
	maxEventsPerCycle   = 500
	highSeverityMax     = 3 // severità 0-3: emerge anche senza flusso
	defaultSeverity     = 4
)

// securityActions sono le azioni che rendono un evento syslog candidato.
var securityActions = []string{
	"deny", "denied", "blocked", "block", "drop",
	"reset-both", "reset-client", "reset-server", "sinkhole",
}

var severityKind = map[int]string{
	0: "critico", 1: "critico", 2: "critico", 3: "alto",
	4: "medio", 5: "medio", 6: "informativo", 7: "informativo",
}

func kindForSeverity(sev int) string {
	if k, ok := severityKind[sev]; ok {
		return k
	}
	return "medio"
}

var (
	reCorrKV = regexp.MustCompile(`(srcip|dstip|dstport)=(?:"([^"]*)"|(\S+))`)
	reCorrIP = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})\b`)
)

// extractEndpoints ricava (src, dst, dstPort) dal messaggio syslog.
// Porta di _extract_endpoints.
func extractEndpoints(message string) (src, dst string, port *int) {
	kv := map[string]string{}
	for _, m := range reCorrKV.FindAllStringSubmatch(message, -1) {
		v := m[2]
		if v == "" {
			v = m[3]
		}
		kv[m[1]] = v
	}
	if kv["srcip"] != "" && kv["dstip"] != "" {
		if raw := kv["dstport"]; raw != "" {
			if p, err := strconv.Atoi(raw); err == nil {
				port = &p
			}
		}
		return kv["srcip"], kv["dstip"], port
	}
	// Palo Alto o formato generico: le prime due IP distinte del messaggio.
	seen := map[string]bool{}
	var ips []string
	for _, m := range reCorrIP.FindAllStringSubmatch(message, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			ips = append(ips, m[1])
		}
	}
	if len(ips) >= 2 {
		return ips[0], ips[1], nil
	}
	return "", "", nil
}

// switchPortFor ritorna "switch:porta" per un client, oppure "" se la
// posizione non è nota. Usa la Client Map (binding ARP + MAC table), che
// esclude già gli uplink, ed è vincolata al tenant dell'evento.
func (m *Manager) switchPortFor(ip, tenant string) string {
	rows, err := m.st.ClientMap("", ip, "", []string{tenant}, 1)
	if err != nil || len(rows) == 0 || rows[0].SwitchPort == "" {
		return ""
	}
	name := rows[0].SwitchName
	if name == "" {
		name = rows[0].SwitchIP
	}
	return name + ":" + rows[0].SwitchPort
}

// CorrelateOnce esegue un ciclo di correlazione e ritorna gli eventi emessi.
//
// Criterio di fondo (precisione prima del richiamo): un evento di sicurezza
// viene emesso solo se esiste un flusso corroborante con gli stessi endpoint
// nello stesso tenant. Fa eccezione l'alta severità, che emerge comunque.
// Nessuna correlazione è mai cross-tenant.
func (m *Manager) CorrelateOnce(now int64) (int, error) {
	events, err := m.obs.SecurityEvents(now-correlationLookback, securityActions,
		highSeverityMax, maxEventsPerCycle)
	if err != nil {
		return 0, err
	}

	emitted := 0
	for _, ev := range events {
		severity := defaultSeverity
		if ev.Severity != nil {
			severity = *ev.Severity
		}
		src, dst, _ := extractEndpoints(ev.Message)

		var flow *obsstore.FlowEvidence
		if src != "" && dst != "" {
			// Il bucket dura 60s, quindi il confronto è sull'inizio finestra.
			flow, err = m.obs.CorroboratingFlow(ev.Tenant, src, dst,
				ev.TS-matchDeltaS-60, ev.TS+matchDeltaS)
			if err != nil {
				return emitted, err
			}
		}

		var kind, dedupKey, evidence string
		switch {
		case flow != nil:
			kind = "traffico_bloccato_" + kindForSeverity(severity)
			dedupKey = sha256Hex(fmt.Sprintf("%s|%s|%d|%s|%s|%s",
				ev.Tenant, kind, ev.ID, src, dst, pyTuple(flow)))
			evidence = mustJSON(map[string]any{
				"syslog_id": ev.ID, "syslog_ts": ev.TS, "action": ev.Action,
				"flow": flow,
			})
		case severity <= highSeverityMax:
			// Alta severità senza flusso corroborante: evento a sé stante,
			// deduplicato sul solo id syslog.
			kind = "syslog_" + kindForSeverity(severity)
			dedupKey = sha256Hex(fmt.Sprintf("%s|%s|%d", ev.Tenant, kind, ev.ID))
			evidence = mustJSON(map[string]any{
				"syslog_id": ev.ID, "syslog_ts": ev.TS,
				"action": ev.Action, "message": ev.Message,
			})
		default:
			continue // niente flusso, niente evento
		}

		switchPort := any(nil)
		if src != "" {
			if p := m.switchPortFor(src, ev.Tenant); p != "" {
				switchPort = p
			}
		}
		m.obs.EnqueueWrite(obsstore.InsertCorrelatedSQL,
			now, ev.Tenant, kind, nullableStr(src), nullableStr(dst), switchPort,
			severity, dedupKey, evidence)
		emitted++
	}

	m.metrics.SetGauge("last_correlation_ts", now)
	m.metrics.Add("correlated_events_emitted", int64(emitted))
	return emitted, nil
}

// pyTuple riproduce la rappresentazione della tupla Python usata nella chiave
// di deduplicazione, così un database condiviso fra le due implementazioni non
// genererebbe duplicati.
func pyTuple(f *obsstore.FlowEvidence) string {
	return "(" + strconv.FormatInt(f.WindowStart, 10) + ", " +
		pyInt(f.Protocol) + ", " + pyInt(f.DstPort) + ")"
}

func pyInt(v *int) string {
	if v == nil {
		return "None"
	}
	return strconv.Itoa(*v)
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
