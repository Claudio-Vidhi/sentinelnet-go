package ingest

import "testing"

// I decoder girano su input che arriva da rete, non autenticato e non
// validato. L'unica garanzia richiesta è che non facciano mai panic: un panic
// dentro la goroutine di un listener terminerebbe il processo.
//
// Esecuzione estesa: go test ./internal/observability/ingest -fuzz FuzzParseSFlow

func FuzzParseSFlow(f *testing.F) {
	f.Add(sflowDatagram(1000, 1500, ipv4Frame(12345, 443)))
	f.Add(sflowDatagram(0, 0, nil))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseSFlow(data, "10.0.0.9", 1_800_000_000)
	})
}

func FuzzParseSyslog(f *testing.F) {
	f.Add([]byte("<134>1 2026-07-12T10:00:00Z host app - - - messaggio"))
	f.Add([]byte("<134>Jul 12 10:00:00 host messaggio"))
	f.Add([]byte(`<134>devid="FGT" logid="1" type="traffic" level="warning" action="blocked"`))
	f.Add([]byte(",THREAT,high,reset-both"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		ParseSyslog(data, "10.0.0.9", refNow)
	})
}
