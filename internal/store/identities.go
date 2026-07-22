package store

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
)

type Identity struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Tenant       string `json:"tenant"`
	Username     string `json:"username"`
	PasswordEnc  string `json:"-"`
	SecretEnc    string `json:"-"`
	DevicesUsing int    `json:"devices_using"`
}

type IdentityCredentials struct {
	Username string
	Password string
	Secret   string
}

func (s *Store) UpsertIdentity(ident *Identity) error {
	ident.Name = strings.TrimSpace(ident.Name)
	ident.Tenant = strings.TrimSpace(ident.Tenant)
	ident.Username = strings.TrimSpace(ident.Username)

	query := `
		INSERT INTO identities (id, name, tenant, username, password_enc, secret_enc)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			tenant = excluded.tenant,
			username = excluded.username,
			password_enc = excluded.password_enc,
			secret_enc = excluded.secret_enc
	`
	_, err := s.DB.Exec(query, ident.ID, ident.Name, ident.Tenant, ident.Username, ident.PasswordEnc, ident.SecretEnc)
	if err != nil {
		return fmt.Errorf("upsert identity failed: %w", err)
	}
	return nil
}

func (s *Store) GetIdentity(id string) (*Identity, error) {
	query := `SELECT id, name, tenant, username, password_enc, secret_enc FROM identities WHERE id = ?`
	row := s.DB.QueryRow(query, id)
	var ident Identity
	err := row.Scan(&ident.ID, &ident.Name, &ident.Tenant, &ident.Username, &ident.PasswordEnc, &ident.SecretEnc)
	if err != nil {
		return nil, err
	}
	return &ident, nil
}

func (s *Store) ListIdentities(tenant string) ([]*Identity, error) {
	var query string
	var args []any
	if tenant != "" {
		query = `SELECT id, name, tenant, username, password_enc, secret_enc FROM identities WHERE tenant = ? ORDER BY name ASC`
		args = append(args, tenant)
	} else {
		query = `SELECT id, name, tenant, username, password_enc, secret_enc FROM identities ORDER BY name ASC`
	}

	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list identities query failed: %w", err)
	}
	defer rows.Close()

	var result []*Identity
	for rows.Next() {
		var ident Identity
		if err := rows.Scan(&ident.ID, &ident.Name, &ident.Tenant, &ident.Username, &ident.PasswordEnc, &ident.SecretEnc); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, &ident)
	}
	rows.Close()

	for _, ident := range result {
		devices, err := s.devicesUsingIdentity(ident.ID)
		if err == nil {
			ident.DevicesUsing = len(devices)
		}
	}
	return result, nil
}

func (s *Store) devicesUsingIdentity(identityID string) ([]string, error) {
	targetProfile := fmt.Sprintf("identity:%s", identityID)
	rows, err := s.DB.Query(`SELECT ip FROM devices WHERE profile = ?`, targetProfile)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

func (s *Store) DeleteIdentity(id string) (bool, []string, error) {
	devices, err := s.devicesUsingIdentity(id)
	if err != nil {
		return false, nil, fmt.Errorf("failed checking identity usage: %w", err)
	}
	if len(devices) > 0 {
		return true, devices, nil // Deletion blocked by devices using this identity
	}

	res, err := s.DB.Exec(`DELETE FROM identities WHERE id = ?`, id)
	if err != nil {
		return false, nil, fmt.Errorf("delete identity failed: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil, sql.ErrNoRows
	}
	return false, nil, nil
}

func (s *Store) GetIdentityCredentials(id string, vault *crypto.Vault) (*IdentityCredentials, error) {
	ident, err := s.GetIdentity(id)
	if err != nil {
		return nil, err
	}
	pass := ""
	if ident.PasswordEnc != "" && vault != nil {
		dec, err := vault.Decrypt(ident.PasswordEnc)
		if err == nil {
			pass = dec
		}
	}
	secret := ""
	if ident.SecretEnc != "" && vault != nil {
		dec, err := vault.Decrypt(ident.SecretEnc)
		if err == nil {
			secret = dec
		}
	}
	return &IdentityCredentials{
		Username: ident.Username,
		Password: pass,
		Secret:   secret,
	}, nil
}
