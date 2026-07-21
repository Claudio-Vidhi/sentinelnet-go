package store

import (
	"database/sql"
	"encoding/json"
)

type User struct {
	Username           string
	HashedPassword     string
	Role               string
	Disabled           bool
	MustChangePassword bool
	Tenants            []string // vuoto = tutti
	// AllowedTabs: tab della dashboard visibili (difetto D5). Vuoto = tutte.
	// Solo interfaccia: nessun controllo d'accesso vi si appoggia.
	AllowedTabs []string
}

// decodeTabs interpreta la colonna allowed_tabs (JSON). Un valore illeggibile
// o nullo diventa lista vuota — "nessuna restrizione" — invece di propagare un
// errore: è una preferenza di interfaccia, non deve poter bloccare il login.
func decodeTabs(raw string) []string {
	out := []string{}
	if raw == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil || out == nil {
		return []string{}
	}
	return out
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) GetUser(username string) (*User, error) {
	u := &User{}
	var disabled, mcp int
	var tabs string
	err := s.DB.QueryRow(`SELECT username, hashed_password, role, disabled, must_change_password, allowed_tabs
		FROM users WHERE username = ?`, username).
		Scan(&u.Username, &u.HashedPassword, &u.Role, &disabled, &mcp, &tabs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MustChangePassword = mcp != 0
	u.AllowedTabs = decodeTabs(tabs)
	u.Tenants, err = s.UserTenants(username)
	return u, err
}

func (s *Store) UserTenants(username string) ([]string, error) {
	rows, err := s.DB.Query(`SELECT tenant FROM user_tenants WHERE username = ? ORDER BY tenant`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) ListUsers() ([]*User, error) {
	rows, err := s.DB.Query(`SELECT username, role, disabled, must_change_password, allowed_tabs FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		var disabled, mcp int
		var tabs string
		if err := rows.Scan(&u.Username, &u.Role, &disabled, &mcp, &tabs); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
		u.MustChangePassword = mcp != 0
		u.AllowedTabs = decodeTabs(tabs)
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, u := range out {
		if u.Tenants, err = s.UserTenants(u.Username); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) CreateUser(username, hashedPassword, role string, mustChange bool) error {
	mcp := 0
	if mustChange {
		mcp = 1
	}
	_, err := s.DB.Exec(`INSERT INTO users(username, hashed_password, role, disabled, must_change_password)
		VALUES(?, ?, ?, 0, ?)`, username, hashedPassword, role, mcp)
	return err
}

func (s *Store) DeleteUser(username string) error {
	if _, err := s.DB.Exec(`DELETE FROM user_tenants WHERE username = ?`, username); err != nil {
		return err
	}
	_, err := s.DB.Exec(`DELETE FROM users WHERE username = ?`, username)
	return err
}

func (s *Store) SetUserRole(username, role string) error {
	_, err := s.DB.Exec(`UPDATE users SET role = ? WHERE username = ?`, role, username)
	return err
}

func (s *Store) SetUserDisabled(username string, disabled bool) error {
	d := 0
	if disabled {
		d = 1
	}
	_, err := s.DB.Exec(`UPDATE users SET disabled = ? WHERE username = ?`, d, username)
	return err
}

func (s *Store) SetUserPassword(username, hashedPassword string) error {
	_, err := s.DB.Exec(`UPDATE users SET hashed_password = ?, must_change_password = 0 WHERE username = ?`, hashedPassword, username)
	return err
}

// SetAllowedTabs imposta le tab visibili di un utente. Lista vuota = tutte.
// Ritorna false se l'utente non esiste (404 lato handler).
func (s *Store) SetAllowedTabs(username string, tabs []string) (bool, error) {
	if tabs == nil {
		tabs = []string{}
	}
	raw, err := json.Marshal(tabs)
	if err != nil {
		return false, err
	}
	res, err := s.DB.Exec(`UPDATE users SET allowed_tabs = ? WHERE username = ?`, string(raw), username)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) SetUserTenants(username string, tenants []string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM user_tenants WHERE username = ?`, username); err != nil {
		return err
	}
	for _, t := range tenants {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO user_tenants(username, tenant) VALUES(?, ?)`, username, t); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AdminCount: admin abilitati (per la regola "mantieni almeno 1 admin").
func (s *Store) AdminCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}
