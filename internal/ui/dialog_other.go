//go:build !windows

package ui

import (
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"
)

// askMode: su Linux/macOS prova un dialog grafico (zenity); se assente ripiega
// sul prompt da terminale, altrimenti nessuna apertura.
func askMode(url string) Mode {
	if m, ok := zenityAsk(); ok {
		return m
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		return promptChoice(url)
	}
	return ModeNone
}

// zenityAsk mostra un dialog a tre scelte con zenity, se disponibile.
//
//	pulsante OK (App integrata)      → exit 0
//	extra-button "Browser"           → exit 1, stdout "Browser\n"
//	Cancel/chiusura (Nessuna)        → exit 1, stdout vuoto
func zenityAsk() (Mode, bool) {
	bin, err := exec.LookPath("zenity")
	if err != nil {
		return "", false
	}
	cmd := exec.Command(bin, "--question",
		"--title=SentinelNet",
		"--text=Come vuoi aprire SentinelNet?",
		"--ok-label=App integrata",
		"--cancel-label=Nessuna",
		"--extra-button=Browser")
	out, runErr := cmd.Output()
	if strings.TrimSpace(string(out)) == "Browser" {
		return ModeBrowser, true
	}
	if runErr == nil {
		return ModeApp, true // OK premuto
	}
	return ModeNone, true // Cancel o chiusura
}
