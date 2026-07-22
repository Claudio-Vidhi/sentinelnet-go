package store

import (
	"database/sql"
	"time"
)

type Device struct {
	IP              string
	Vendor          string
	Profile         string
	Username        string
	PasswordEnc     string
	EnableSecretEnc string
	Tenant          string
	Hostname        string
	Site            string
	SSHPort         int
	Transports      string // JSON {protocollo: porta|null}; "" = solo ssh sulla SSHPort
}

type DetectedVersion struct {
	IP        string
	Vendor    string
	Version   string
	Status    string
	UpdatedAt string
}

type Tenant struct {
	Name        string
	Description string
}

// ---- Devices ----

func scanDevice(row interface{ Scan(...any) error }) (*Device, error) {
	d := &Device{}
	err := row.Scan(&d.IP, &d.Vendor, &d.Profile, &d.Username, &d.PasswordEnc, &d.EnableSecretEnc,
		&d.Tenant, &d.Hostname, &d.Site, &d.SSHPort, &d.Transports)
	if err != nil {
		return nil, err
	}
	return d, nil
}

const deviceCols = `ip, vendor, profile, username, password_enc, enable_secret_enc, tenant, hostname, site, ssh_port, transports`

func (s *Store) GetDevice(ip string) (*Device, error) {
	d, err := scanDevice(s.DB.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE ip = ?`, ip))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return d, err
}

func (s *Store) ListDevices() ([]*Device, error) {
	rows, err := s.DB.Query(`SELECT ` + deviceCols + ` FROM devices ORDER BY tenant, ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) UpsertDevice(d *Device) error {
	port := d.SSHPort
	if port == 0 {
		port = 22
	}
	_, err := s.DB.Exec(`INSERT INTO devices(`+deviceCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET vendor=excluded.vendor, profile=excluded.profile,
			username=excluded.username, password_enc=excluded.password_enc,
			enable_secret_enc=excluded.enable_secret_enc, tenant=excluded.tenant,
			hostname=excluded.hostname, site=excluded.site,
			ssh_port=excluded.ssh_port, transports=excluded.transports`,
		d.IP, d.Vendor, d.Profile, d.Username, d.PasswordEnc, d.EnableSecretEnc, d.Tenant, d.Hostname,
		d.Site, port, d.Transports)
	return err
}

func (s *Store) DeleteDevice(ip string) error {
	if _, err := s.DB.Exec(`DELETE FROM detected_versions WHERE ip = ?`, ip); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM devices WHERE ip = ?`, ip)
	return err
}

func (s *Store) SetDeviceHostname(ip, hostname string) error {
	_, err := s.DB.Exec(`UPDATE devices SET hostname = ? WHERE ip = ?`, hostname, ip)
	return err
}

func (s *Store) SetDeviceTenant(ip, tenant string) error {
	_, err := s.DB.Exec(`UPDATE devices SET tenant = ? WHERE ip = ?`, tenant, ip)
	return err
}

// UpsertDeviceForPromotion crea un gestito da un vicino scoperto senza toccare
// le credenziali di un device già esistente (profile=default).
func (s *Store) UpsertDeviceForPromotion(ip, vendor, tenant, hostname string) error {
	_, err := s.DB.Exec(`INSERT INTO devices(ip, vendor, profile, username, password_enc, enable_secret_enc, tenant, hostname)
		VALUES(?, ?, 'default', '', '', '', ?, ?)
		ON CONFLICT(ip) DO UPDATE SET tenant=excluded.tenant,
			hostname=CASE WHEN excluded.hostname != '' THEN excluded.hostname ELSE devices.hostname END`,
		ip, vendor, tenant, hostname)
	return err
}

// ---- Detected versions ----

func (s *Store) ListVersions() (map[string]*DetectedVersion, error) {
	rows, err := s.DB.Query(`SELECT ip, COALESCE(vendor,''), COALESCE(version,''), COALESCE(status,''), COALESCE(updated_at,'') FROM detected_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*DetectedVersion{}
	for rows.Next() {
		v := &DetectedVersion{}
		if err := rows.Scan(&v.IP, &v.Vendor, &v.Version, &v.Status, &v.UpdatedAt); err != nil {
			return nil, err
		}
		out[v.IP] = v
	}
	return out, rows.Err()
}

func (s *Store) UpsertVersion(ip, vendor, version, status string) error {
	_, err := s.DB.Exec(`INSERT INTO detected_versions(ip, vendor, version, status, updated_at) VALUES(?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET vendor=excluded.vendor, version=excluded.version,
			status=excluded.status, updated_at=excluded.updated_at`,
		ip, vendor, version, status, time.Now().Format(time.RFC3339))
	return err
}

// SetVersionStatus aggiorna solo lo stato (ping check) preservando la versione.
func (s *Store) SetVersionStatus(ip, status string) error {
	_, err := s.DB.Exec(`INSERT INTO detected_versions(ip, vendor, version, status, updated_at) VALUES(?, '', 'Non Scansionato', ?, ?)
		ON CONFLICT(ip) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at`,
		ip, status, time.Now().Format(time.RFC3339))
	return err
}

// ---- Tenants ----

func (s *Store) ListTenants() ([]*Tenant, error) {
	rows, err := s.DB.Query(`SELECT name, COALESCE(description,'') FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tenant
	for rows.Next() {
		t := &Tenant{}
		if err := rows.Scan(&t.Name, &t.Description); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) TenantExists(name string) (bool, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM tenants WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

func (s *Store) CreateTenant(name, description string) error {
	_, err := s.DB.Exec(`INSERT INTO tenants(name, description) VALUES(?, ?)`, name, description)
	return err
}

// DeleteTenant sposta i device del tenant in "Generale" e lo elimina.
func (s *Store) DeleteTenant(name string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE devices SET tenant = 'Generale' WHERE tenant = ?`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM user_tenants WHERE tenant = ?`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM tenants WHERE name = ?`, name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RenameTenant(oldName, newName string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE tenants SET name = ? WHERE name = ?`, newName, oldName); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE devices SET tenant = ? WHERE tenant = ?`, newName, oldName); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE user_tenants SET tenant = ? WHERE tenant = ?`, newName, oldName); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE mac_sightings SET tenant = ? WHERE tenant = ?`, newName, oldName); err != nil {
		return err
	}
	return tx.Commit()
}

// ---- Vendors / Models ----

type VendorMeta struct {
	EUVDTerm string `json:"euvd_term"`
	Driver   string `json:"driver"`
}

// ListVendors: merge dei vendor di sistema con quelli custom.
func (s *Store) ListVendors() (map[string]VendorMeta, error) {
	out := map[string]VendorMeta{
		"cisco":      {EUVDTerm: "cisco", Driver: "cisco_ios"},
		"cisco_cbs":  {EUVDTerm: "cisco", Driver: "cisco_s300"},
		"hpe":        {EUVDTerm: "hewlett packard enterprise", Driver: "hp_procurve"},
		"juniper":    {EUVDTerm: "juniper networks", Driver: "juniper_junos"},
		"aruba":      {EUVDTerm: "aruba networks", Driver: "aruba_os"},
		"fortinet":   {EUVDTerm: "fortinet", Driver: "fortinet"},
		"paloalto":   {EUVDTerm: "palo alto networks", Driver: "paloalto_panos"},
		"cisco_wlc":  {EUVDTerm: "cisco", Driver: "cisco_wlc"},
		"cisco_9800": {EUVDTerm: "cisco", Driver: "cisco_9800"},
	}
	rows, err := s.DB.Query(`SELECT name, COALESCE(euvd_term,''), COALESCE(driver,'') FROM vendors`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var m VendorMeta
		if err := rows.Scan(&name, &m.EUVDTerm, &m.Driver); err != nil {
			return nil, err
		}
		out[name] = m
	}
	return out, rows.Err()
}

func (s *Store) UpsertVendor(name, euvdTerm, driver string) error {
	_, err := s.DB.Exec(`INSERT INTO vendors(name, euvd_term, driver) VALUES(?,?,?)
		ON CONFLICT(name) DO UPDATE SET euvd_term=excluded.euvd_term, driver=excluded.driver`,
		name, euvdTerm, driver)
	return err
}

func (s *Store) DeleteVendor(name string) error {
	_, err := s.DB.Exec(`DELETE FROM vendors WHERE name = ?`, name)
	return err
}

func (s *Store) ListModels() (map[string][]string, error) {
	rows, err := s.DB.Query(`SELECT vendor, model FROM models ORDER BY vendor, model`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var v, m string
		if err := rows.Scan(&v, &m); err != nil {
			return nil, err
		}
		out[v] = append(out[v], m)
	}
	return out, rows.Err()
}

func (s *Store) AddModel(vendor, model string) error {
	_, err := s.DB.Exec(`INSERT OR IGNORE INTO models(vendor, model) VALUES(?, ?)`, vendor, model)
	return err
}

func (s *Store) DeleteModel(vendor, model string) error {
	_, err := s.DB.Exec(`DELETE FROM models WHERE vendor = ? AND model = ?`, vendor, model)
	return err
}
