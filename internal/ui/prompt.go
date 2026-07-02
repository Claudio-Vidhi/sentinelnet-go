package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// promptChoice interroga l'utente sul terminale (fallback quando non è
// disponibile una finestra di dialogo nativa).
func promptChoice(url string) Mode {
	fmt.Println()
	fmt.Println("SentinelNet è pronto. Scegli come aprire l'interfaccia:")
	fmt.Println("  [1] App integrata  — finestra dedicata senza barra indirizzi (Edge/Chrome)")
	fmt.Println("  [2] Browser        — apri nel browser predefinito")
	fmt.Println("  [3] Nessuna        — solo server, apri tu " + url)
	fmt.Print("Scelta [1/2/3] (default 2): ")

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	switch strings.TrimSpace(line) {
	case "1":
		return ModeApp
	case "3":
		return ModeNone
	default:
		return ModeBrowser
	}
}
