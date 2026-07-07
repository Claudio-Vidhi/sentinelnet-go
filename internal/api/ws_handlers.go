package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
)

// handleWSToken emette un OTP monouso a breve scadenza per aprire la WS.
func (a *App) handleWSToken(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	tok, err := a.auth.IssueWSToken(claims.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ws_token": tok})
}

// handleWSTerminal collega la WS del browser a una shell SSH sull'apparato.
// L'autenticazione avviene tramite l'OTP monouso passato in query (?token=).
func (a *App) handleWSTerminal(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	otp := r.URL.Query().Get("token")
	username, ok := a.auth.ConsumeWSToken(otp)
	if !ok {
		http.Error(w, "token OTP non valido o scaduto", http.StatusUnauthorized)
		return
	}

	// Verifica ruolo e scoping del richiedente sul device.
	u, err := a.store.GetUser(username)
	if err != nil || u == nil || u.Disabled || !roleAtLeast(u.Role, "operator") {
		http.Error(w, "privilegi insufficienti", http.StatusForbidden)
		return
	}
	d, err := a.store.GetDevice(ip)
	if err != nil || d == nil {
		http.Error(w, "dispositivo non trovato", http.StatusNotFound)
		return
	}
	if u.Role != "admin" {
		if scoped, _ := a.tenantsForUser(u.Username, u.Role); !canSeeTenant(scoped, d.Tenant) {
			http.Error(w, "dispositivo fuori dal tuo ambito", http.StatusForbidden)
			return
		}
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusInternalError, "chiusura")

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Dati dall'apparato → browser.
	bridge, err := collect.DialInteractive(ctx, ip, a.resolveCreds(d), func(b []byte) {
		wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
		defer wcancel()
		_ = conn.Write(wctx, websocket.MessageText, b)
	})
	if err != nil {
		_ = conn.Write(ctx, websocket.MessageText, []byte("\r\n[Errore] Connessione SSH fallita: "+err.Error()+"\r\n"))
		conn.Close(websocket.StatusNormalClosure, "ssh error")
		return
	}
	defer bridge.Close()

	// La sessione SSH si chiude → annulla il contesto.
	go func() {
		_ = bridge.Wait()
		cancel()
	}()

	// Input dal browser → apparato: ogni carattere viene inoltrato subito
	// (l'eco arriva dall'apparato), mentre una copia "ombra" della riga in
	// corso viene bufferizzata per validarla con isCommandSafe() all'Invio.
	// Porto di ws_to_ssh() in app_server.py.
	var lineBuf strings.Builder
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText && typ != websocket.MessageBinary {
			continue
		}
		for _, ch := range string(data) {
			switch {
			case ch == '\r' || ch == '\n':
				line := strings.TrimSpace(lineBuf.String())
				if line != "" && !isCommandSafe(line) {
					if _, err := bridge.Write([]byte{0x15}); err != nil { // Ctrl-U: cancella la riga sull'apparato
						return
					}
					wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
					_ = conn.Write(wctx, websocket.MessageText, []byte(
						"\r\n[Comando bloccato] Operazione non consentita per motivi di sicurezza (in blacklist).\r\n"))
					wcancel()
					a.auditLog("Comando da terminale bloccato per blacklist ('" + line + "') su '" + ip +
						"' dall'utente '" + username + "'.")
					lineBuf.Reset()
					continue
				}
				lineBuf.Reset()
				if _, err := bridge.Write([]byte{byte(ch)}); err != nil {
					return
				}
			case ch == '\x7f' || ch == '\x08': // backspace
				s := lineBuf.String()
				if len(s) > 0 {
					lineBuf.Reset()
					lineBuf.WriteString(s[:len(s)-1])
				}
				if _, err := bridge.Write([]byte{byte(ch)}); err != nil {
					return
				}
			case ch == '\x03': // Ctrl-C: azzera la riga corrente
				lineBuf.Reset()
				if _, err := bridge.Write([]byte{byte(ch)}); err != nil {
					return
				}
			default:
				lineBuf.WriteRune(ch)
				if _, err := bridge.Write([]byte(string(ch))); err != nil {
					return
				}
			}
		}
	}
}
