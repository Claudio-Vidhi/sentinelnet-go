//go:build windows

package ui

import (
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procMessageBoxW      = user32.NewProc("MessageBoxW")
	procCreateActCtxW    = kernel32.NewProc("CreateActCtxW")
	procActivateActCtx   = kernel32.NewProc("ActivateActCtx")
	procDeactivateActCtx = kernel32.NewProc("DeactivateActCtx")
	procReleaseActCtx    = kernel32.NewProc("ReleaseActCtx")
)

// askMode mostra la finestra di scelta dell'interfaccia. Prova prima un
// TaskDialog moderno con pulsanti etichettati (App / Browser / Solo server);
// se non disponibile ripiega su una MessageBox nativa.
func askMode(url string) Mode {
	if m, ok := taskDialogAsk(url); ok {
		return m
	}
	return messageBoxAsk(url)
}

// IDs dei pulsanti command-link del TaskDialog.
const (
	btnApp     = 101
	btnBrowser = 102
	btnNone    = 103
)

// taskDialogAsk mostra un dialog con tre command-link chiari. Ritorna ok=false
// se il TaskDialog non è utilizzabile (così il chiamante usa la MessageBox).
func taskDialogAsk(url string) (mode Mode, ok bool) {
	// Un pointer errato passato a Win32 crasherebbe: proteggi con recover e
	// ripiega sulla MessageBox in caso di problemi.
	defer func() {
		if r := recover(); r != nil {
			mode, ok = "", false
		}
	}()

	// Prepara stringhe e buffer PRIMA di attivare il contesto (nessuna
	// rischedulazione critica tra activate e la chiamata al dialog).
	title := utf16("SentinelNet")
	instr := utf16("Come vuoi aprire l'interfaccia di SentinelNet?")
	content := utf16("La scelta è ricordabile con l'opzione -ui (app | browser | none).")
	items := []struct {
		id   int32
		text string
	}{
		{btnApp, "App integrata\nFinestra dedicata senza barra indirizzi (Edge/Chrome)"},
		{btnBrowser, "Browser\nApri nel browser predefinito del sistema"},
		{btnNone, "Solo server\nNon aprire nulla — apri tu " + url},
	}
	buttonsBuf := make([]byte, 12*len(items))
	texts := make([]*uint16, len(items))
	for i, it := range items {
		texts[i] = utf16(it.text)
		binary.LittleEndian.PutUint32(buttonsBuf[i*12:], uint32(it.id))
		binary.LittleEndian.PutUint64(buttonsBuf[i*12+4:], ptrToU64(unsafe.Pointer(texts[i])))
	}

	const (
		tdfAllowDialogCancellation = 0x0008
		tdfUseCommandLinks         = 0x0010
		tdfPositionRelativeToWindow = 0x0000
	)

	// TASKDIALOGCONFIG è impacchettato a 1 byte (pshpack1.h): costruiamo i 160
	// byte a mano per garantire l'esatto layout su 64 bit.
	cfg := make([]byte, 160)
	binary.LittleEndian.PutUint32(cfg[0:], 160) // cbSize
	binary.LittleEndian.PutUint32(cfg[20:], tdfUseCommandLinks|tdfAllowDialogCancellation)
	binary.LittleEndian.PutUint64(cfg[28:], ptrToU64(unsafe.Pointer(title)))   // pszWindowTitle
	binary.LittleEndian.PutUint64(cfg[44:], ptrToU64(unsafe.Pointer(instr)))   // pszMainInstruction
	binary.LittleEndian.PutUint64(cfg[52:], ptrToU64(unsafe.Pointer(content))) // pszContent
	binary.LittleEndian.PutUint32(cfg[60:], uint32(len(items)))                // cButtons
	binary.LittleEndian.PutUint64(cfg[64:], ptrToU64(unsafe.Pointer(&buttonsBuf[0]))) // pButtons
	binary.LittleEndian.PutUint32(cfg[72:], btnApp)                            // nDefaultButton

	// TaskDialog richiede i Common Controls v6: attivali via manifest a runtime.
	release, ok := enableVisualStyles()
	if !ok {
		return "", false
	}
	defer release()

	taskDialog := syscall.NewLazyDLL("comctl32.dll").NewProc("TaskDialogIndirect")
	if err := taskDialog.Find(); err != nil {
		return "", false
	}

	var pressed int32
	ret, _, _ := taskDialog.Call(
		uintptr(unsafe.Pointer(&cfg[0])),
		uintptr(unsafe.Pointer(&pressed)),
		0, 0,
	)
	runtime.KeepAlive(title)
	runtime.KeepAlive(instr)
	runtime.KeepAlive(content)
	runtime.KeepAlive(texts)
	runtime.KeepAlive(buttonsBuf)
	runtime.KeepAlive(cfg)

	if ret != 0 { // S_OK == 0
		return "", false
	}
	switch pressed {
	case btnApp:
		return ModeApp, true
	case btnBrowser:
		return ModeBrowser, true
	default: // btnNone o chiusura del dialog (IDCANCEL)
		return ModeNone, true
	}
}

// ACTCTXW (allineamento naturale).
type actCtxW struct {
	cbSize                 uint32
	dwFlags                uint32
	lpSource               *uint16
	wProcessorArchitecture uint16
	wLangID                uint16
	lpAssemblyDirectory    *uint16
	lpResourceName         *uint16
	lpApplicationName      *uint16
	hModule                uintptr
}

// enableVisualStyles crea e attiva un contesto con i Common Controls v6 (serve
// a TaskDialog). Ritorna una funzione di rilascio e ok=false in caso di errore.
func enableVisualStyles() (release func(), ok bool) {
	const manifest = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency><dependentAssembly><assemblyIdentity
    type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
    processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
</assembly>`

	f, err := os.CreateTemp("", "sentinelnet-*.manifest")
	if err != nil {
		return nil, false
	}
	path := f.Name()
	_, _ = f.WriteString(manifest)
	_ = f.Close()

	var ctx actCtxW
	ctx.cbSize = uint32(unsafe.Sizeof(ctx))
	ctx.lpSource = utf16(path)
	h, _, _ := procCreateActCtxW.Call(uintptr(unsafe.Pointer(&ctx)))
	invalid := ^uintptr(0) // INVALID_HANDLE_VALUE
	if h == 0 || h == invalid {
		os.Remove(path)
		return nil, false
	}

	// Il contesto di attivazione è per-thread: blocca il goroutine sul thread.
	runtime.LockOSThread()
	var cookie uintptr
	r, _, _ := procActivateActCtx.Call(h, uintptr(unsafe.Pointer(&cookie)))
	if r == 0 {
		runtime.UnlockOSThread()
		procReleaseActCtx.Call(h)
		os.Remove(path)
		return nil, false
	}
	return func() {
		procDeactivateActCtx.Call(0, cookie)
		procReleaseActCtx.Call(h)
		runtime.UnlockOSThread()
		os.Remove(path)
	}, true
}

// messageBoxAsk è il fallback: una MessageBox Sì/No/Annulla con testo esplicito.
func messageBoxAsk(url string) Mode {
	const (
		mbYesNoCancel   = 0x00000003
		mbIconQuestion  = 0x00000020
		mbSetForeground = 0x00010000
		mbTopmost       = 0x00040000
		idCancel        = 2
		idYes           = 6
		idNo            = 7
	)
	text := "Come vuoi aprire SentinelNet?\r\n\r\n" +
		"Sì  →  App integrata (finestra dedicata)\r\n" +
		"No  →  Browser predefinito\r\n" +
		"Annulla  →  Nessuna (apri tu " + url + ")"
	t, _ := syscall.UTF16PtrFromString(text)
	c, _ := syscall.UTF16PtrFromString("SentinelNet — Interfaccia")
	ret, _, _ := procMessageBoxW.Call(0,
		uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(c)),
		uintptr(mbYesNoCancel|mbIconQuestion|mbSetForeground|mbTopmost))
	switch int(ret) {
	case idYes:
		return ModeApp
	case idNo:
		return ModeBrowser
	default:
		return ModeNone
	}
}

func utf16(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func ptrToU64(p unsafe.Pointer) uint64 { return uint64(uintptr(p)) }
