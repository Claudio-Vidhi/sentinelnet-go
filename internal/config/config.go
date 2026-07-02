// Package config carica la configurazione da variabili d'ambiente.
package config

import (
	"os"
	"path/filepath"
)

type Config struct {
	Addr    string // indirizzo di ascolto HTTP (es. ":8000")
	DataDir string // directory dati: SQLite, chiavi, backup-config, audit.log

	JWTSecret []byte // firmato HS256; se vuoto viene generato/persistito su file

	// Credenziali del "Profilo Rete Standard" per gli apparati con profile=default.
	DefaultUser   string
	DefaultPass   string
	DefaultSecret string
}

func Load() *Config {
	cfg := &Config{
		Addr:          envOr("SENTINELNET_ADDR", ":8000"),
		DataDir:       envOr("SENTINELNET_DATA_DIR", "data"),
		JWTSecret:     []byte(os.Getenv("SENTINELNET_JWT_SECRET")),
		DefaultUser:   os.Getenv("SENTINELNET_DEFAULT_USER"),
		DefaultPass:   os.Getenv("SENTINELNET_DEFAULT_PASS"),
		DefaultSecret: os.Getenv("SENTINELNET_DEFAULT_SECRET"),
	}
	return cfg
}

func (c *Config) DBPath() string        { return filepath.Join(c.DataDir, "sentinelnet.db") }
func (c *Config) BackupDir() string     { return filepath.Join(c.DataDir, "backup-config") }
func (c *Config) AuditLogPath() string  { return filepath.Join(c.DataDir, "audit.log") }
func (c *Config) MasterKeyPath() string { return filepath.Join(c.DataDir, "secret.key") }
func (c *Config) JWTKeyPath() string    { return filepath.Join(c.DataDir, "jwt_secret.key") }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
