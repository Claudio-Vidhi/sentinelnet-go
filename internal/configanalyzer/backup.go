package configanalyzer

import (
	"os"
	"path/filepath"
	"strings"
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

// AnalyzeDevice legge il backup piu' recente per l'IP e ritorna analisi + meta.
// invGroup/invHostname provengono dall'inventario (possono essere ""): il gruppo
// dell'inventario ha priorita' sul tenant dedotto dalla cartella; l'hostname
// dell'inventario e' un fallback se manca nella config. Ritorna nil se non
// esiste alcun backup per l'IP.
func AnalyzeDevice(backupDir, ip, invGroup, invHostname string) *DeviceResult {
	path, tenantFolder := FindFreshestBackup(backupDir, ip)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)

	res := &DeviceResult{Analysis: AnalyzeConfig(content)}

	hostname := HostnameFromConfig(content)
	tenant := tenantFolder
	if invGroup != "" {
		tenant = invGroup
	}
	if hostname == "" {
		hostname = invHostname
	}

	res.IP = ip
	res.Hostname = hostname
	res.Tenant = tenant
	res.VTP = ParseVTPStatus(content)
	return res
}
