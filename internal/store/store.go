// Package store: layer SQLite (modernc.org/sqlite, senza CGO) con migrazioni embed.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	DB *sql.DB
}

func MustOpen(path string) *Store {
	s, err := Open(path)
	if err != nil {
		panic(err)
	}
	return s
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Scritture serializzate da una singola connessione (equivalente dell'_io_lock).
	db.SetMaxOpenConns(1)
	s := &Store{DB: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.seed(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT)`); err != nil {
		return err
	}
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, name := range entries {
		// Ogni migrazione è applicata una sola volta: alcuni statement (es.
		// ALTER TABLE ADD COLUMN) non sono idempotenti.
		var applied int
		if err := s.DB.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
			return err
		}
		if applied > 0 {
			continue
		}
		sqlBytes, err := migrationsFS.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := s.DB.Exec(string(sqlBytes)); err != nil {
			return fmt.Errorf("migrazione %s: %w", name, err)
		}
		if _, err := s.DB.Exec(`INSERT INTO schema_migrations(name, applied_at) VALUES(?, datetime('now'))`, name); err != nil {
			return err
		}
	}
	return nil
}

// seed: tenant "Generale" e categorie builtin sempre presenti.
func (s *Store) seed() error {
	if _, err := s.DB.Exec(`INSERT OR IGNORE INTO tenants(name, description) VALUES('Generale', 'Sede Principale predefinita')`); err != nil {
		return err
	}
	builtins := map[string]string{
		"switch": "Switch", "router": "Router", "firewall": "Firewall",
		"wlc": "WLC", "ap": "Access Point", "server": "Server",
		"phone": "Telefono IP", "pc": "PC", "other": "Altro",
	}
	for k, label := range builtins {
		if _, err := s.DB.Exec(`INSERT OR IGNORE INTO categories(key, label, builtin) VALUES(?, ?, 1)`, k, label); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetSetting(key, def string) string {
	var v string
	err := s.DB.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err != nil {
		return def
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.DB.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
