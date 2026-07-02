package api

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// deviceJSON: chiavi maiuscole come nel frontend (d.IP, d.Vendor, d.Group, d.Hostname).
type deviceJSON struct {
	IP       string `json:"IP"`
	Vendor   string `json:"Vendor"`
	Group    string `json:"Group"`
	Hostname string `json:"Hostname"`
	Profile  string `json:"Profile"`
}

func (a *App) handleLocalDevices(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, err := a.tenantsForUser(claims.Username, claims.Role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	devices, err := a.store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	versions, err := a.store.ListVersions()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	tenants, err := a.store.ListTenants()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	devOut := []deviceJSON{}
	detected := map[string]map[string]string{}
	for _, d := range devices {
		if !canSeeTenant(scoped, d.Tenant) {
			continue
		}
		devOut = append(devOut, deviceJSON{
			IP: d.IP, Vendor: d.Vendor, Group: d.Tenant, Hostname: d.Hostname, Profile: d.Profile,
		})
		if v, ok := versions[d.IP]; ok {
			detected[d.IP] = map[string]string{"version": v.Version, "status": v.Status, "vendor": v.Vendor}
		}
	}

	groups := map[string]map[string]string{}
	for _, t := range tenants {
		if scoped != nil && !canSeeTenant(scoped, t.Name) {
			continue
		}
		groups[t.Name] = map[string]string{"description": t.Description}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"devices":           devOut,
		"groups":            groups,
		"detected_versions": detected,
	})
}

type addDeviceReq struct {
	IP           string `json:"ip"`
	Vendor       string `json:"vendor"`
	Profile      string `json:"profile"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	EnableSecret string `json:"enable_secret"`
	Group        string `json:"group"`
}

func (a *App) handleAddDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req addDeviceReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP == "" {
		writeErr(w, http.StatusBadRequest, "IP obbligatorio")
		return
	}
	if req.Group == "" {
		req.Group = "Generale"
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, req.Group) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return
	}
	if req.Vendor == "" {
		req.Vendor = "cisco"
	}
	if req.Profile == "" {
		req.Profile = "default"
	}
	passEnc, err := a.vault.Encrypt(req.Password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	secEnc, err := a.vault.Encrypt(req.EnableSecret)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Preserva l'hostname già noto in caso di ri-provisioning.
	hostname := ""
	if existing, _ := a.store.GetDevice(req.IP); existing != nil {
		hostname = existing.Hostname
	}
	d := &store.Device{
		IP: req.IP, Vendor: strings.ToLower(req.Vendor), Profile: req.Profile,
		Username: req.Username, PasswordEnc: passEnc, EnableSecretEnc: secEnc,
		Tenant: req.Group, Hostname: hostname,
	}
	if err := a.store.UpsertDevice(d); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type ipReq struct {
	IP string `json:"ip"`
}

func (a *App) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	var req ipReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !a.deviceIPInScope(w, r, req.IP) {
		return
	}
	if err := a.store.DeleteDevice(req.IP); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type renameReq struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

func (a *App) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	var req renameReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !a.deviceIPInScope(w, r, req.IP) {
		return
	}
	if err := a.store.SetDeviceHostname(req.IP, strings.TrimSpace(req.Hostname)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type reassignReq struct {
	IP       string `json:"ip"`
	NewGroup string `json:"new_group"`
}

func (a *App) handleReassignDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req reassignReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if !a.deviceIPInScope(w, r, req.IP) {
		return
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, req.NewGroup) {
		writeErr(w, http.StatusForbidden, "tenant di destinazione non consentito")
		return
	}
	if ok, _ := a.store.TenantExists(req.NewGroup); !ok {
		writeErr(w, http.StatusBadRequest, "tenant inesistente")
		return
	}
	if err := a.store.SetDeviceTenant(req.IP, req.NewGroup); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleExportDevices(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	devices, err := a.store.ListDevices()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	versions, _ := a.store.ListVersions()
	var buf bytes.Buffer
	buf.WriteString("\uFEFF") // BOM per Excel
	cw := csv.NewWriter(&buf)
	_ = cw.Write([]string{"IP", "Hostname", "Group", "Vendor", "Version", "Status"})
	for _, d := range devices {
		if !canSeeTenant(scoped, d.Tenant) {
			continue
		}
		ver, status := "", ""
		if v, ok := versions[d.IP]; ok {
			ver, status = v.Version, v.Status
		}
		_ = cw.Write([]string{d.IP, d.Hostname, d.Tenant, d.Vendor, ver, status})
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=sentinelnet-devices.csv")
	w.Write(buf.Bytes())
}

type importCSVReq struct {
	CSVData string `json:"csv_data"`
}

func (a *App) handleImportCSV(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	var req importCSVReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	reader := csv.NewReader(strings.NewReader(req.CSVData))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil || len(records) < 1 {
		writeErr(w, http.StatusBadRequest, "CSV non valido")
		return
	}
	// Intestazione attesa: IP,Username,Password,Enable Secret,Hostname,Group,Vendor
	imported := []string{}
	failed := []map[string]any{}
	for i, rec := range records {
		if i == 0 {
			continue // header
		}
		if len(rec) < 7 {
			failed = append(failed, map[string]any{"row": i + 1, "ip": firstOr(rec, 0), "error": "colonne insufficienti"})
			continue
		}
		ip := strings.TrimSpace(rec[0])
		if ip == "" {
			failed = append(failed, map[string]any{"row": i + 1, "ip": "", "error": "IP mancante"})
			continue
		}
		group := strings.TrimSpace(rec[5])
		if group == "" {
			group = "Generale"
		}
		if !canSeeTenant(scoped, group) {
			failed = append(failed, map[string]any{"row": i + 1, "ip": ip, "error": "tenant non consentito"})
			continue
		}
		// Crea il tenant se non esiste ancora.
		if ok, _ := a.store.TenantExists(group); !ok {
			_ = a.store.CreateTenant(group, "Sede secondaria "+group)
		}
		passEnc, _ := a.vault.Encrypt(strings.TrimSpace(rec[2]))
		secEnc, _ := a.vault.Encrypt(strings.TrimSpace(rec[3]))
		d := &store.Device{
			IP: ip, Vendor: strings.ToLower(strings.TrimSpace(rec[6])), Profile: "custom",
			Username: strings.TrimSpace(rec[1]), PasswordEnc: passEnc, EnableSecretEnc: secEnc,
			Tenant: group, Hostname: strings.TrimSpace(rec[4]),
		}
		if d.Vendor == "" {
			d.Vendor = "cisco"
		}
		if err := a.store.UpsertDevice(d); err != nil {
			failed = append(failed, map[string]any{"row": i + 1, "ip": ip, "error": err.Error()})
			continue
		}
		imported = append(imported, ip)
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported, "failed": failed})
}

func firstOr(rec []string, i int) string {
	if i < len(rec) {
		return rec[i]
	}
	return ""
}

// ---- helper scoping device ----

func (a *App) deviceIPInScope(w http.ResponseWriter, r *http.Request, ip string) bool {
	claims := claimsFrom(r.Context())
	if claims.Role == "admin" {
		return true
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if scoped == nil {
		return true
	}
	d, err := a.store.GetDevice(ip)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return false
	}
	if d == nil {
		writeErr(w, http.StatusNotFound, "dispositivo non trovato")
		return false
	}
	if !canSeeTenant(scoped, d.Tenant) {
		writeErr(w, http.StatusForbidden, "dispositivo fuori dal tuo ambito")
		return false
	}
	return true
}
