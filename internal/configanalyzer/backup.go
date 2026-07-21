package configanalyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fwanalyzer"
)

// FindFreshestBackup trova il file di backup piu' recente per l'IP dato dentro
// backupDir. Ritorna (path, tenantFolder). path == "" se non esiste alcun backup.
// tenantFolder e' il primo segmento del percorso relativo a backupDir.
func FindFreshestBackup(backupDir, ip string) (string, string) {
	info, err := os.Stat(backupDir)
	if err != nil || !info.IsDir() {
		return "", ""
	}
	var best, bestTenant string
	var bestMtime int64 = -1
	_ = filepath.Walk(backupDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		f := fi.Name()
		if strings.HasSuffix(f, "-"+ip+".txt") || strings.HasSuffix(f, "_"+ip+".txt") || f == ip+".txt" {
			mt := fi.ModTime().UnixNano()
			if mt > bestMtime {
				bestMtime = mt
				best = p
				rel, _ := filepath.Rel(backupDir, filepath.Dir(p))
				if rel == "." || rel == "" {
					bestTenant = ""
				} else {
					bestTenant = strings.Split(filepath.ToSlash(rel), "/")[0]
				}
			}
		}
		return nil
	})
	return best, bestTenant
}

var rePanosHostname = regexp.MustCompile(`(?m)^set deviceconfig system hostname (\S+)`)

// AnalyzeDevice legge il backup piu' recente per l'IP e ritorna analisi + meta.
// vendor/invGroup/invHostname provengono dall'inventario (possono essere ""):
// il vendor guida il rilevamento del tipo, il gruppo ha priorita' sul tenant
// dedotto dalla cartella, l'hostname e' un fallback se manca nella config.
// Ritorna nil se non esiste alcun backup per l'IP.
//
// Il risultato e' polimorfo per tipo di config (porta di analyze_device): un
// FortiGate e un IOS hanno chiavi diverse sotto gli stessi nomi (es.
// interfaces), quindi si assembla una mappa a partire dai sotto-analizzatori
// gia' verificati, mettendo le stesse chiavi del Python — vtp solo per IOS,
// firewall null per IOS e l'envelope per i firewall.
func AnalyzeDevice(backupDir, ip, vendor, invGroup, invHostname string) any {
	path, tenantFolder := FindFreshestBackup(backupDir, ip)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)

	configType := fwanalyzer.DetectConfigType(content, vendor)

	var result map[string]any
	var hostname string
	isFirewall := false
	var firewall any // null per IOS, envelope per i firewall

	switch configType {
	case fwanalyzer.TypeFortiOS:
		fa := fwanalyzer.AnalyzeFortiOSStructured(content)
		hostname = fa.Hostname
		result = structToMap(fa)
		delete(result, "hostname") // reinserito nel meta comune
		isFirewall = true
		firewall = fwanalyzer.AnalyzeFortiOS(content)
	case fwanalyzer.TypePanOS:
		// PAN-OS: nessun analizzatore strutturato dedicato — le tab riusano il
		// parser IOS in modo tollerante; la tab Firewall usa l'envelope.
		result = structToMap(AnalyzeConfig(content))
		if m := rePanosHostname.FindStringSubmatch(content); m != nil {
			hostname = m[1]
		}
		isFirewall = true
		firewall = fwanalyzer.AnalyzePanos(content)
	default:
		// IOS (e wlc-aireos, non ancora portato: analizzato come IOS, come
		// prima di questo dispatch — vedi DIVERGENZE §10).
		result = structToMap(AnalyzeConfig(content))
		hostname = HostnameFromConfig(content)
		result["vtp"] = ParseVTPStatus(content)
	}

	tenant := tenantFolder
	if invGroup != "" {
		tenant = invGroup
	}
	if hostname == "" {
		hostname = invHostname
	}

	result["ip"] = ip
	result["hostname"] = hostname
	result["tenant"] = tenant
	result["config_type"] = configType
	result["is_firewall"] = isFirewall
	result["firewall"] = firewall
	return result
}

// structToMap serializza un valore e lo rilegge come mappa, così i campi del
// sotto-analizzatore (gia' verificati col golden) finiscono al livello
// superiore com'e' nel Python. Vuota in caso di errore, che qui non capita.
func structToMap(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]any{}
	}
	return m
}
