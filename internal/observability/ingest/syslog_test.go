package ingest

import (
	"strings"
	"testing"
	"time"
)

var refNow = time.Date(2026, time.July, 12, 10, 0, 0, 0, time.UTC)

func TestParseSyslogPriority(t *testing.T) {
	// PRI 134 = facility 16, severity 6.
	ev := ParseSyslog([]byte("<134>test messaggio"), "10.0.0.1", refNow)
	if len(ev) != 1 {
		t.Fatalf("eventi = %d, atteso 1", len(ev))
	}
	if ev[0].Severity != 6 {
		t.Errorf("severity = %d, attesa 6", ev[0].Severity)
	}
	if ev[0].Message != "test messaggio" {
		t.Errorf("message = %q — il PRI non è stato rimosso", ev[0].Message)
	}
	if ev[0].ExporterIP != "10.0.0.1" || ev[0].DeviceIP != "10.0.0.1" {
		t.Errorf("exporter/device = %q/%q", ev[0].ExporterIP, ev[0].DeviceIP)
	}
}

func TestParseSyslogRFC5424Timestamp(t *testing.T) {
	ev := ParseSyslog([]byte("<134>1 2026-07-12T10:00:00Z host app - - - messaggio"), "10.0.0.1", refNow)
	want := time.Date(2026, time.July, 12, 10, 0, 0, 0, time.UTC).Unix()
	if ev[0].TS != want {
		t.Errorf("ts = %d, atteso %d", ev[0].TS, want)
	}
}

func TestParseSyslogBSDTimestamp(t *testing.T) {
	ev := ParseSyslog([]byte("<134>Jul 12 10:00:00 host messaggio"), "10.0.0.1", refNow)
	want := time.Date(refNow.Year(), time.July, 12, 10, 0, 0, 0, refNow.Location()).Unix()
	if ev[0].TS != want {
		t.Errorf("ts = %d, atteso %d", ev[0].TS, want)
	}
}

// Senza timestamp riconoscibile si usa l'ora di ricezione.
func TestParseSyslogFallsBackToNow(t *testing.T) {
	ev := ParseSyslog([]byte("messaggio senza data"), "10.0.0.1", refNow)
	if ev[0].TS != refNow.Unix() {
		t.Errorf("ts = %d, atteso %d (ora di ricezione)", ev[0].TS, refNow.Unix())
	}
}

func TestParseSyslogFortiGate(t *testing.T) {
	msg := `<134>date=2026-07-12 devid="FGT60F" logid="0000000013" type="traffic" ` +
		`level="warning" action="blocked" srcip=10.0.0.5`
	ev := ParseSyslog([]byte(msg), "10.0.0.1", refNow)
	if ev[0].Action != "blocked" {
		t.Errorf("action = %q, attesa %q", ev[0].Action, "blocked")
	}
	// level="warning" del vendor prevale sulla severity del PRI.
	if ev[0].Severity != 4 {
		t.Errorf("severity = %d, attesa 4 (warning)", ev[0].Severity)
	}
}

func TestParseSyslogPaloAltoThreat(t *testing.T) {
	msg := "<134>1,2026/07/12 10:00:00,001801,THREAT,vulnerability,10,2026/07/12 10:00:00," +
		"10.0.0.5,10.0.0.9,,,regola,,,web-browsing,,,,,,,,,,,,,,,,,,reset-both,,,,high"
	ev := ParseSyslog([]byte(msg), "10.0.0.1", refNow)
	if ev[0].Action != "reset-both" {
		t.Errorf("action = %q, attesa %q", ev[0].Action, "reset-both")
	}
	if ev[0].Severity != 3 {
		t.Errorf("severity = %d, attesa 3 (high)", ev[0].Severity)
	}
}

func TestParseSyslogPaloAltoTraffic(t *testing.T) {
	msg := "<134>1,2026/07/12 10:00:00,001801,TRAFFIC,end,10,,10.0.0.5,10.0.0.9,,,regola,,,,,,allow"
	ev := ParseSyslog([]byte(msg), "10.0.0.1", refNow)
	if ev[0].Action != "allow" {
		t.Errorf("action = %q, attesa %q", ev[0].Action, "allow")
	}
}

// Formato sconosciuto: nessuna azione, messaggio preservato. Non è un errore.
func TestParseSyslogUnknownFormatPreservesMessage(t *testing.T) {
	ev := ParseSyslog([]byte("qualcosa di completamente diverso"), "10.0.0.1", refNow)
	if ev[0].Action != "" {
		t.Errorf("action = %q, attesa vuota", ev[0].Action)
	}
	if ev[0].Message != "qualcosa di completamente diverso" {
		t.Errorf("message = %q", ev[0].Message)
	}
}

func TestParseSyslogTruncatesLongMessage(t *testing.T) {
	ev := ParseSyslog([]byte(strings.Repeat("x", MaxMessageLen*2)), "10.0.0.1", refNow)
	if len(ev[0].Message) != MaxMessageLen {
		t.Errorf("lunghezza = %d, attesa %d", len(ev[0].Message), MaxMessageLen)
	}
}

// Nessun input, per quanto malformato, deve provocare un panic: un panic in
// una goroutine di listener ucciderebbe il processo.
func TestParseSyslogNeverPanics(t *testing.T) {
	inputs := [][]byte{
		nil, {}, []byte("<"), []byte("<>"), []byte("<999>"), []byte("<134>"),
		[]byte("<134>1 "), []byte("<134>1 non-una-data host"),
		[]byte("<134>Xyz 99 99:99:99 host"), []byte("<134>Feb 30 10:00:00 host"),
		{0xff, 0xfe, 0x00, 0x01}, []byte("logid= devid= type="),
		[]byte(",THREAT,"), []byte(",TRAFFIC,"),
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic su %q: %v", in, r)
				}
			}()
			ParseSyslog(in, "10.0.0.1", refNow)
		}()
	}
}
