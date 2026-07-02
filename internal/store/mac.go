package store

import (
	"fmt"
	"strings"
	"time"
)

type MacSighting struct {
	Mac         string `json:"mac"`
	OuiVendor   string `json:"oui_vendor"`
	Vlan        string `json:"vlan"`
	SwitchIP    string `json:"switch_ip"`
	SwitchName  string `json:"switch_name"`
	Interface   string `json:"interface"`
	PortChannel string `json:"port_channel"`
	IsUplink    bool   `json:"is_uplink"`
	Tenant      string `json:"tenant"`
	FirstSeen   string `json:"first_seen"`
	LastSeen    string `json:"last_seen"`
	SeenCount   int    `json:"seen_count"`
}

type MacOverride struct {
	SwitchIP string `json:"switch_ip"`
	Command  string `json:"command"`
	Fmt      string `json:"fmt"`
}

func (s *Store) UpsertSighting(m *MacSighting) error {
	now := time.Now().Format(time.RFC3339)
	uplink := 0
	if m.IsUplink {
		uplink = 1
	}
	_, err := s.DB.Exec(`INSERT INTO mac_sightings
		(mac, oui_vendor, vlan, switch_ip, switch_name, interface, port_channel, is_uplink, tenant, first_seen, last_seen, seen_count)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
		ON CONFLICT(mac, switch_ip, interface, vlan) DO UPDATE SET
			oui_vendor=excluded.oui_vendor, switch_name=excluded.switch_name,
			port_channel=excluded.port_channel, is_uplink=excluded.is_uplink,
			tenant=excluded.tenant, last_seen=excluded.last_seen,
			seen_count=mac_sightings.seen_count+1`,
		m.Mac, m.OuiVendor, m.Vlan, m.SwitchIP, m.SwitchName, m.Interface, m.PortChannel, uplink, m.Tenant, now, now)
	return err
}

// SearchSightings: filtri opzionali; tenants limita la visibilità (vuoto = tutti).
func (s *Store) SearchSightings(mac, vlan, iface, switchIP string, tenants []string, limit int) ([]*MacSighting, error) {
	q := `SELECT mac, oui_vendor, vlan, switch_ip, switch_name, interface, port_channel, is_uplink, tenant, first_seen, last_seen, seen_count
		FROM mac_sightings WHERE 1=1`
	var args []any
	if mac != "" {
		norm := normalizeMacFragment(mac)
		q += ` AND REPLACE(REPLACE(REPLACE(mac,':',''),'-',''),'.','') LIKE ?`
		args = append(args, "%"+norm+"%")
	}
	if vlan != "" {
		q += ` AND vlan = ?`
		args = append(args, vlan)
	}
	if iface != "" {
		q += ` AND (interface LIKE ? OR port_channel LIKE ?)`
		args = append(args, "%"+iface+"%", "%"+iface+"%")
	}
	if switchIP != "" {
		q += ` AND switch_ip = ?`
		args = append(args, switchIP)
	}
	if len(tenants) > 0 {
		q += ` AND tenant IN (?` + strings.Repeat(",?", len(tenants)-1) + `)`
		for _, t := range tenants {
			args = append(args, t)
		}
	}
	q += ` ORDER BY last_seen DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*MacSighting{}
	for rows.Next() {
		m := &MacSighting{}
		var uplink int
		if err := rows.Scan(&m.Mac, &m.OuiVendor, &m.Vlan, &m.SwitchIP, &m.SwitchName, &m.Interface,
			&m.PortChannel, &uplink, &m.Tenant, &m.FirstSeen, &m.LastSeen, &m.SeenCount); err != nil {
			return nil, err
		}
		m.IsUplink = uplink != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func normalizeMacFragment(mac string) string {
	r := strings.NewReplacer(":", "", "-", "", ".", "", " ", "")
	return strings.ToLower(r.Replace(mac))
}

func (s *Store) MacStats() (sightings, uniqueMacs, switches int, err error) {
	err = s.DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT mac), COUNT(DISTINCT switch_ip) FROM mac_sightings`).
		Scan(&sightings, &uniqueMacs, &switches)
	return
}

// PruneSightings elimina gli avvistamenti più vecchi di retentionDays.
func (s *Store) PruneSightings(retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	res, err := s.DB.Exec(`DELETE FROM mac_sightings WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) ListMacOverrides() ([]*MacOverride, error) {
	rows, err := s.DB.Query(`SELECT switch_ip, command, COALESCE(fmt,'generic') FROM mac_cmd_overrides ORDER BY switch_ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*MacOverride{}
	for rows.Next() {
		o := &MacOverride{}
		if err := rows.Scan(&o.SwitchIP, &o.Command, &o.Fmt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (s *Store) GetMacOverride(switchIP string) (*MacOverride, error) {
	o := &MacOverride{}
	err := s.DB.QueryRow(`SELECT switch_ip, command, COALESCE(fmt,'generic') FROM mac_cmd_overrides WHERE switch_ip = ?`, switchIP).
		Scan(&o.SwitchIP, &o.Command, &o.Fmt)
	if err != nil {
		return nil, nil //nolint:nilerr // assenza override non è un errore
	}
	return o, nil
}

func (s *Store) UpsertMacOverride(switchIP, command, fmtName string) error {
	_, err := s.DB.Exec(`INSERT INTO mac_cmd_overrides(switch_ip, command, fmt) VALUES(?,?,?)
		ON CONFLICT(switch_ip) DO UPDATE SET command=excluded.command, fmt=excluded.fmt`,
		switchIP, command, fmtName)
	return err
}

func (s *Store) DeleteMacOverride(switchIP string) error {
	_, err := s.DB.Exec(`DELETE FROM mac_cmd_overrides WHERE switch_ip = ?`, switchIP)
	return err
}

func (s *Store) RetentionDays() int {
	v := s.GetSetting("mac_retention_days", "90")
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
		return 90
	}
	return n
}
