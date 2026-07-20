// Package obsstore: persistenza della pipeline di osservabilità
// (observability.db). Porta di core/db.py.
//
// È un database SEPARATO da sentinelnet.db, come nel Python: l'ingest UDP
// scrive a volumi molto più alti del resto dell'applicazione e la retention
// oraria cancella a blocchi, quindi le due cose non devono contendere con
// letture e scritture di inventario e autenticazione.
//
// Tutte le scritture passano dalla coda del writer (writer.go): una sola
// connessione in scrittura, commit a batch.
package obsstore

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/metrics"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Store struct {
	DB      *sql.DB
	Metrics *metrics.Registry

	queue  chan writeJob
	done   chan struct{}
	closed chan struct{}
}

// Open apre (creando se serve) observability.db e avvia il writer.
// Chiudere con Close per svuotare la coda.
func Open(path string, m *metrics.Registry) (*Store, error) {
	if m == nil {
		m = metrics.New()
	}
	dsn := fmt.Sprintf(
		"file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)",
		path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// Una sola connessione in scrittura, come il thread writer del Python.
	db.SetMaxOpenConns(1)

	s := &Store{
		DB:      db,
		Metrics: m,
		queue:   make(chan writeJob, QueueMax),
		done:    make(chan struct{}),
		closed:  make(chan struct{}),
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	go s.writerLoop()
	return s, nil
}

// Close ferma il writer dopo aver svuotato la coda e chiude il database.
func (s *Store) Close() error {
	close(s.done)
	<-s.closed
	return s.DB.Close()
}

func (s *Store) migrate() error {
	if _, err := s.DB.Exec(
		`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT)`); err != nil {
		return err
	}
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(entries)
	for _, name := range entries {
		var applied int
		if err := s.DB.QueryRow(
			`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
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
		if _, err := s.DB.Exec(
			`INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`,
			name, time.Now().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}

// DBSizeBytes ritorna la dimensione del database, per l'endpoint di health.
func (s *Store) DBSizeBytes() int64 {
	var pageCount, pageSize int64
	if err := s.DB.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0
	}
	if err := s.DB.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0
	}
	return pageCount * pageSize
}
