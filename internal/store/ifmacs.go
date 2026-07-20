package store

import (
	"strings"
	"time"
)

// SwitchIfMac identifica il MAC di un'interfaccia propria di uno switch.
type SwitchIfMac struct {
	SwitchIP   string `json:"switch_ip"`
	SwitchName string `json:"switch_name"`
	Interface  string `json:"interface"`
}

// IfMacInput è una riga grezza da registrare (MAC non ancora canonicalizzato).
type IfMacInput struct {
	Interface string
	Mac       string
}

// RecordSwitchIfMacs registra (upsert) i MAC delle interfacce proprie di UNO
// switch. Chiave: (mac, switch_ip, interface).
func (s *Store) RecordSwitchIfMacs(rows []IfMacInput, switchIP, switchName string) (new, updated, skipped int, err error) {
	now := time.Now().Format(time.RFC3339)
	tx, err := s.DB.Begin()
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback()

	for _, r := range rows {
		mac, ok := normalizeMacStrict(r.Mac)
		iface := strings.TrimSpace(r.Interface)
		if !ok || iface == "" {
			skipped++
			continue
		}
		res, err := tx.Exec(`UPDATE switch_if_macs SET last_seen=?, switch_name=?
			WHERE mac=? AND switch_ip=? AND interface=?`, now, switchName, mac, switchIP, iface)
		if err != nil {
			return 0, 0, 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			updated++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO switch_if_macs(mac, switch_ip, switch_name, interface, last_seen)
			VALUES(?,?,?,?,?)`, mac, switchIP, switchName, iface, now); err != nil {
			return 0, 0, 0, err
		}
		new++
	}
	return new, updated, skipped, tx.Commit()
}

// SwitchIfMacs ritorna { mac canonicalizzato: interfaccia dello switch }, per la
// classificazione read-time degli avvistamenti come infrastruttura.
func (s *Store) SwitchIfMacs() (map[string]SwitchIfMac, error) {
	rows, err := s.DB.Query(`SELECT mac, switch_ip, switch_name, interface FROM switch_if_macs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SwitchIfMac{}
	for rows.Next() {
		var m string
		var v SwitchIfMac
		if err := rows.Scan(&m, &v.SwitchIP, &v.SwitchName, &v.Interface); err != nil {
			return nil, err
		}
		out[m] = v
	}
	return out, rows.Err()
}
