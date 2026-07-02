//go:build windows

package ui

import (
	"syscall"
	"testing"
)

// Verifica che il contesto di attivazione dei Common Controls v6 funzioni e che
// TaskDialogIndirect sia risolvibile: così askMode userà il TaskDialog moderno
// (pulsanti etichettati) invece del fallback MessageBox. Non mostra alcun dialog.
func TestVisualStylesEnablesTaskDialog(t *testing.T) {
	release, ok := enableVisualStyles()
	if !ok {
		t.Fatal("attivazione Common Controls v6 fallita")
	}
	defer release()

	proc := syscall.NewLazyDLL("comctl32.dll").NewProc("TaskDialogIndirect")
	if err := proc.Find(); err != nil {
		t.Fatalf("TaskDialogIndirect non risolto: %v", err)
	}
}
