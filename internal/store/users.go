package store

import "database/sql"

type User struct {
	Username           string
	HashedPassword     string
	Role               string
	Disabled           bool
	MustChangePassword bool
	Tenants            []string // vuoto = tutti
}

func (s *Store) UserCount() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) GetUser(username string) (*User, error) {
	u := &User{}
	var disabled, mcp int
	err := s.DB.QueryRow(`SELECT username, hashed_password, role, disabled, must_change_password
		FROM users WHERE username = ?`, username).
		Scan(&u.Username, &u.HashedPassword, &u.Role, &disabled, &mcp)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MustChangePassword = mcp != 0
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
	rows, err := s.DB.Query(`SELECT username, role, disabled, must_change_password FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		var disabled, mcp int
		if err := rows.Scan(&u.Username, &u.Role, &disabled, &mcp); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
		u.MustChangePassword = mcp != 0
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
