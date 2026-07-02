package api

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeartbeatRecordsBeatAnd204(t *testing.T) {
	app := NewApp(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	app.handleHeartbeat(rec, httptest.NewRequest("POST", "/api/heartbeat", nil))
	if rec.Code != 204 {
		t.Fatalf("atteso 204, ottenuto %d", rec.Code)
	}
	if app.lastBeat.Load() == 0 {
		t.Fatal("lastBeat non aggiornato dall'heartbeat")
	}
}

func TestMonitorLivenessShutsDownWhenHeartbeatsStop(t *testing.T) {
	app := NewApp(nil, nil, nil, nil)
	done := make(chan struct{})
	app.SetOnShutdown(func() { close(done) })
	app.EnableAutoShutdown()
	app.lastBeat.Store(time.Now().UnixNano()) // primo battito, poi silenzio
	go app.MonitorLiveness(200 * time.Millisecond)

	select {
	case <-done: // arresto avvenuto: corretto
	case <-time.After(6 * time.Second):
		t.Fatal("il server non si è arrestato dopo lo stop degli heartbeat")
	}
}

func TestMonitorLivenessStaysUpWhileBeating(t *testing.T) {
	app := NewApp(nil, nil, nil, nil)
	fired := make(chan struct{}, 1)
	app.SetOnShutdown(func() { fired <- struct{}{} })
	app.EnableAutoShutdown()
	app.lastBeat.Store(time.Now().UnixNano())
	go app.MonitorLiveness(1 * time.Second)

	deadline := time.After(3 * time.Second)
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			app.lastBeat.Store(time.Now().UnixNano())
		case <-fired:
			t.Fatal("arresto nonostante gli heartbeat continui")
		case <-deadline:
			return // ha retto: corretto
		}
	}
}

func TestAutoShutdownDisabledByDefault(t *testing.T) {
	app := NewApp(nil, nil, nil, nil)
	fired := make(chan struct{}, 1)
	app.SetOnShutdown(func() { fired <- struct{}{} })
	// autoShutdown NON attivato: MonitorLiveness deve uscire subito senza arresto.
	go app.MonitorLiveness(50 * time.Millisecond)
	select {
	case <-fired:
		t.Fatal("arresto con auto-shutdown disattivo")
	case <-time.After(500 * time.Millisecond):
	}
}
