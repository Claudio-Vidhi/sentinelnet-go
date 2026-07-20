// Package ingest: decodifica dei protocolli di telemetria (syslog, sFlow,
// NetFlow/IPFIX) verso record normalizzati.
//
// Regola comune a tutti i decoder, ereditata dal Python: un input malformato
// non deve mai far cadere il chiamante. Dove il Python si affida a un
// try/except globale, qui servono controlli di lunghezza espliciti a ogni
// offset — in Go un panic dentro la goroutine di un listener ucciderebbe il
// processo, che è peggio dell'eccezione catturata del Python.
package ingest

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// MaxMessageLen tronca il messaggio conservato (minimizzazione dei log).
const MaxMessageLen = 2048

// SyslogEvent è un evento syslog normalizzato.
type SyslogEvent struct {
	TS         int64
	DeviceIP   string
	Severity   int // -1 = assente
	Action     string
	Message    string
	ExporterIP string
}

var (
	rePRI     = regexp.MustCompile(`^<(\d{1,3})>`)
	reRFC5424 = regexp.MustCompile(`^(\d)\s+(\S+)\s+(\S+)\s+`)
	reBSDTS   = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+`)
	reFgtKV   = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)
)

var months = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

var fgtLevels = map[string]int{
	"emergency": 0, "alert": 1, "critical": 2, "error": 3,
	"warning": 4, "notice": 5, "information": 6, "debug": 7,
}

// ParseSyslog decodifica un messaggio syslog (RFC 3164 o RFC 5424) con
// normalizzazione vendor per FortiGate e Palo Alto.
//
// Ritorna al più un evento, per uniformità con gli altri decoder. Un formato
// sconosciuto non è un errore: si conserva il messaggio grezzo troncato con
// Action vuota.
func ParseSyslog(data []byte, exporterIP string, now time.Time) []SyslogEvent {
	severity := -1
	if m := rePRI.FindSubmatch(data); m != nil {
		if pri, err := strconv.Atoi(string(m[1])); err == nil {
			severity = pri & 0x07
		}
		data = data[len(m[0]):]
	}
	text := strings.TrimSpace(string(data))

	ts, ok := extractSyslogTS(text, now)
	if !ok {
		ts = now.Unix()
	}
	action, vendorSeverity := vendorNormalize(text)
	if vendorSeverity >= 0 {
		severity = vendorSeverity
	}
	if len(text) > MaxMessageLen {
		text = text[:MaxMessageLen]
	}
	return []SyslogEvent{{
		TS: ts, DeviceIP: exporterIP, Severity: severity,
		Action: action, Message: text, ExporterIP: exporterIP,
	}}
}

func extractSyslogTS(text string, now time.Time) (int64, bool) {
	// RFC 5424: "1 2026-07-12T10:00:00.000Z host ..."
	if m := reRFC5424.FindStringSubmatch(text); m != nil && m[1] == "1" {
		for _, layout := range []string{
			time.RFC3339Nano, time.RFC3339,
			"2006-01-02T15:04:05.999999", "2006-01-02T15:04:05",
		} {
			if t, err := time.Parse(layout, m[2]); err == nil {
				return t.Unix(), true
			}
		}
	}
	// RFC 3164: "Jul 12 10:00:00 host ..." — senza anno né fuso orario: si
	// assume l'anno corrente e il fuso locale del server, limite noto del
	// formato BSD.
	if m := reBSDTS.FindStringSubmatch(text); m != nil {
		mon, ok := months[m[1]]
		if !ok {
			return 0, false
		}
		day, _ := strconv.Atoi(m[2])
		hh, _ := strconv.Atoi(m[3])
		mm, _ := strconv.Atoi(m[4])
		ss, _ := strconv.Atoi(m[5])
		return time.Date(now.Year(), mon, day, hh, mm, ss, 0, now.Location()).Unix(), true
	}
	return 0, false
}

var panActions = map[string]bool{
	"allow": true, "deny": true, "drop": true, "reset-both": true,
	"reset-client": true, "reset-server": true, "alert": true,
	"block": true, "sinkhole": true,
}

var panSeverity = map[string]int{
	"critical": 2, "high": 3, "medium": 4, "low": 5, "informational": 6,
}

// vendorNormalize estrae azione e severità dai formati vendor noti.
// Severità -1 significa "non determinata dal vendor".
func vendorNormalize(text string) (action string, severity int) {
	// FortiGate: corpo key=value.
	if strings.Contains(text, "logid=") ||
		(strings.Contains(text, "devid=") && strings.Contains(text, "type=")) {
		kv := map[string]string{}
		for _, m := range reFgtKV.FindAllStringSubmatch(text, -1) {
			v := m[2]
			if v == "" {
				v = m[3]
			}
			kv[m[1]] = v
		}
		action = kv["action"]
		if action == "" {
			action = kv["utmaction"]
		}
		if lvl, ok := fgtLevels[strings.ToLower(kv["level"])]; ok {
			return action, lvl
		}
		return action, -1
	}

	// Palo Alto: CSV, campo 4 = tipo (TRAFFIC/THREAT). La posizione di action
	// varia per versione, quindi si cerca il primo valore fra quelli noti.
	isThreat := strings.Contains(text, ",THREAT,")
	if strings.Contains(text, ",TRAFFIC,") || isThreat {
		severity = -1
		for _, f := range strings.Split(text, ",") {
			f = strings.TrimSpace(f)
			low := strings.ToLower(f)
			if action == "" && panActions[low] {
				action = f
			}
			if isThreat && severity < 0 {
				if s, ok := panSeverity[low]; ok {
					severity = s
				}
			}
		}
		return action, severity
	}
	return "", -1
}
