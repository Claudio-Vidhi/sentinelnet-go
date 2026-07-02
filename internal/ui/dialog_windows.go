//go:build windows

package ui

import (
	"syscall"
	"unsafe"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

// Flag e valori di ritorno di MessageBoxW (Win32).
const (
	mbYesNoCancel   = 0x00000003
	mbIconQuestion  = 0x00000020
	mbSetForeground = 0x00010000
	mbTopmost       = 0x00040000
	idCancel        = 2
	idYes           = 6
	idNo            = 7
)

// askMode mostra una finestra di dialogo nativa (Sì/No/Annulla) per scegliere
// l'interfaccia. Funziona anche senza console (doppio clic sull'eseguibile).
func askMode(url string) Mode {
	text := "Come vuoi aprire SentinelNet?\r\n\r\n" +
		"Sì  →  App integrata (finestra dedicata)\r\n" +
		"No  →  Browser predefinito\r\n" +
		"Annulla  →  Nessuna (apri tu " + url + ")"
	switch messageBox(text, "SentinelNet — Interfaccia", mbYesNoCancel|mbIconQuestion|mbSetForeground|mbTopmost) {
	case idYes:
		return ModeApp
	case idNo:
		return ModeBrowser
	default: // idCancel o chiusura del dialogo
		return ModeNone
	}
}

func messageBox(text, caption string, flags uintptr) int {
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString(caption)
	ret, _, _ := procMessageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)), flags)
	return int(ret)
}
