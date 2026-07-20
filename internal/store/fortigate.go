package store

import "database/sql"

// FortiGateTarget è un FortiGate raggiungibile via REST.
// TokenEnc è cifrato: la decifratura avviene nel layer che possiede il vault.
type FortiGateTarget struct {
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Port      int    `json:"port"`
	VerifyTLS bool   `json:"verify_tls"`
	TokenEnc  string `json:"-"`
	Active    bool   `json:"active"`
}

func (s *Store) ListFortiGateTargets() ([]*FortiGateTarget, error) {
	rows, err := s.DB.Query(`SELECT ip, name, port, verify_tls, token_enc, active
		FROM fortigate_targets ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*FortiGateTarget{}
	for rows.Next() {
		t := &FortiGateTarget{}
		if err := rows.Scan(&t.IP, &t.Name, &t.Port, &t.VerifyTLS, &t.TokenEnc, &t.Active); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) GetFortiGateTarget(ip string) (*FortiGateTarget, error) {
	t := &FortiGateTarget{}
	err := s.DB.QueryRow(`SELECT ip, name, port, verify_tls, token_enc, active
		FROM fortigate_targets WHERE ip = ?`, ip).
		Scan(&t.IP, &t.Name, &t.Port, &t.VerifyTLS, &t.TokenEnc, &t.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// UpsertFortiGateTarget salva un target. Un token vuoto conserva quello già
// memorizzato: la UI mostra "•••• invariato" e non deve costringere a
// reinserirlo per rinominare il target o cambiarne la porta.
func (s *Store) UpsertFortiGateTarget(t *FortiGateTarget) error {
	if t.Port == 0 {
		t.Port = 443
	}
	_, err := s.DB.Exec(`INSERT INTO fortigate_targets(ip, name, port, verify_tls, token_enc)
		VALUES(?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET
			name=excluded.name, port=excluded.port, verify_tls=excluded.verify_tls,
			token_enc=CASE WHEN excluded.token_enc != '' THEN excluded.token_enc
			               ELSE fortigate_targets.token_enc END`,
		t.IP, t.Name, t.Port, t.VerifyTLS, t.TokenEnc)
	return err
}

// DeleteFortiGateTarget rimuove un target (token compreso).
func (s *Store) DeleteFortiGateTarget(ip string) error {
	_, err := s.DB.Exec(`DELETE FROM fortigate_targets WHERE ip = ?`, ip)
	return err
}

// SetActiveFortiGateTarget rende attivo un solo target.
func (s *Store) SetActiveFortiGateTarget(ip string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE fortigate_targets SET active = 0`); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE fortigate_targets SET active = 1 WHERE ip = ?`, ip); err != nil {
		return err
	}
	return tx.Commit()
}

// ActiveFortiGateTarget ritorna il target attivo, o nil se nessuno lo è.
func (s *Store) ActiveFortiGateTarget() (*FortiGateTarget, error) {
	t := &FortiGateTarget{}
	err := s.DB.QueryRow(`SELECT ip, name, port, verify_tls, token_enc, active
		FROM fortigate_targets WHERE active = 1 LIMIT 1`).
		Scan(&t.IP, &t.Name, &t.Port, &t.VerifyTLS, &t.TokenEnc, &t.Active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}
