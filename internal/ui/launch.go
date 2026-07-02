// Package ui avvia l'interfaccia utente: una finestra "app" dedicata (Edge/Chrome
// in modalità --app, aspetto nativo derivato dall'HTML) oppure il browser predefinito.
// La scelta della modalità avviene con una finestra di dialogo nativa (vedi dialog_*.go).
package ui

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// Mode è la modalità di interfaccia scelta all'avvio.
type Mode string

const (
	ModeApp     Mode = "app"     // finestra app dedicata (chromeless)
	ModeBrowser Mode = "browser" // browser predefinito
	ModeNone    Mode = "none"    // solo server, nessuna finestra
	ModeAsk     Mode = "ask"     // chiedi con una finestra di dialogo all'avvio
)

var errNoChromium = errors.New("nessun browser Chromium (Edge/Chrome) trovato per la modalità app")

// Resolve determina la modalità effettiva: usa quella richiesta, e se è "ask"
// mostra una finestra di dialogo nativa (fallback al prompt su terminale).
func Resolve(requested Mode, url string) Mode {
	switch requested {
	case ModeApp, ModeBrowser, ModeNone:
		return requested
	}
	return askMode(url) // definito per piattaforma (dialog_windows.go / dialog_other.go)
}

// Launch apre l'interfaccia secondo la modalità scelta, attendendo che il server
// sia raggiungibile. Per la modalità "app" ritorna il processo del browser: chi
// chiama può attenderne l'uscita (chiusura finestra) per arrestare il server.
func Launch(mode Mode, addr, url string) (*exec.Cmd, error) {
	if mode == ModeNone {
		return nil, nil
	}
	if !waitReady(addr, 5*time.Second) {
		return nil, errors.New("server non raggiungibile: interfaccia non avviata")
	}
	switch mode {
	case ModeApp:
		cmd, err := OpenAppWindow(url)
		if err != nil {
			// Fallback automatico al browser se manca un browser Chromium.
			return nil, OpenBrowser(url)
		}
		return cmd, nil
	default: // ModeBrowser
		return nil, OpenBrowser(url)
	}
}

// OpenBrowser apre l'URL nel browser predefinito del sistema.
func OpenBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

// OpenAppWindow apre l'URL come finestra applicazione senza barra indirizzi
// (Edge/Chrome con --app), con un profilo dedicato così il processo resta vivo
// finché la finestra è aperta ed esce alla sua chiusura (tracciabile).
func OpenAppWindow(url string) (*exec.Cmd, error) {
	bin := findChromium()
	if bin == "" {
		return nil, errNoChromium
	}
	cmd := exec.Command(bin,
		"--app="+url,
		"--user-data-dir="+appProfileDir(),
		"--no-first-run",
		"--no-default-browser-check",
		"--new-window",
	)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// appProfileDir: profilo persistente dedicato alla finestra app (ricorda
// dimensioni/posizione). Un profilo separato garantisce un processo proprio,
// così la chiusura della finestra corrisponde all'uscita del processo.
func appProfileDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	dir := filepath.Join(base, "SentinelNet", "ui-profile")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// findChromium individua un browser Chromium (Edge preferito su Windows, poi Chrome).
func findChromium() string {
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		pf := os.Getenv("ProgramFiles")
		pfx86 := os.Getenv("ProgramFiles(x86)")
		local := os.Getenv("LocalAppData")
		candidates = []string{
			pfx86 + `\Microsoft\Edge\Application\msedge.exe`,
			pf + `\Microsoft\Edge\Application\msedge.exe`,
			pf + `\Google\Chrome\Application\chrome.exe`,
			pfx86 + `\Google\Chrome\Application\chrome.exe`,
			local + `\Google\Chrome\Application\chrome.exe`,
		}
	case "darwin":
		candidates = []string{
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		}
	default:
		for _, name := range []string{"microsoft-edge", "google-chrome", "chromium", "chromium-browser"} {
			if p, err := exec.LookPath(name); err == nil {
				return p
			}
		}
		return ""
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if info, err := os.Stat(c); err == nil && !info.IsDir() {
			return c
		}
	}
	return ""
}

// waitReady attende che l'indirizzo TCP accetti connessioni, entro timeout.
func waitReady(addr string, timeout time.Duration) bool {
	dialAddr := addr
	if len(addr) > 0 && addr[0] == ':' {
		dialAddr = "127.0.0.1" + addr
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		d := net.Dialer{Timeout: 300 * time.Millisecond}
		conn, err := d.DialContext(ctx, "tcp", dialAddr)
		if err == nil {
			conn.Close()
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(150 * time.Millisecond):
		}
	}
}
