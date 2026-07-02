package api

import (
	"net/http"
	"time"
)

// SetOnShutdown registra la callback da eseguire quando l'interfaccia si chiude.
func (a *App) SetOnShutdown(fn func()) { a.onShutdown = fn }

// EnableAutoShutdown attiva l'arresto automatico basato sull'heartbeat della UI.
func (a *App) EnableAutoShutdown() { a.autoShutdown.Store(true) }

// TriggerShutdown esegue la callback di arresto una sola volta.
func (a *App) TriggerShutdown() {
	if a.onShutdown != nil {
		a.shutdownOnce.Do(a.onShutdown)
	}
}

// handleHeartbeat: la pagina lo chiama periodicamente per segnalare che è aperta.
func (a *App) handleHeartbeat(w http.ResponseWriter, _ *http.Request) {
	a.lastBeat.Store(time.Now().UnixNano())
	w.WriteHeader(http.StatusNoContent)
}

// MonitorLiveness arresta il server quando smettono di arrivare heartbeat per
// più di grace (interfaccia chiusa). Non fa nulla se l'auto-shutdown è disattivo
// o finché non è arrivato il primo battito (server appena avviato).
func (a *App) MonitorLiveness(grace time.Duration) {
	if !a.autoShutdown.Load() {
		return
	}
	// Attendi il primo heartbeat: se l'interfaccia non si apre mai, il server
	// resta comunque in ascolto (nessun falso arresto).
	for a.lastBeat.Load() == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		last := time.Unix(0, a.lastBeat.Load())
		if time.Since(last) > grace {
			a.TriggerShutdown()
			return
		}
	}
}
