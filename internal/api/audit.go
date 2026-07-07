package api

import (
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// auditLog registra una riga di audit su data/audit.log (best-effort, come
// log_audit() in Python). Non blocca la richiesta se la scrittura fallisce.
func (a *App) auditLog(msg string) {
	if a.cfg == nil {
		slog.Info("audit", "msg", msg)
		return
	}
	path := a.cfg.AuditLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		slog.Warn("audit log: mkdir fallita", "err", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		slog.Warn("audit log: apertura fallita", "err", err)
		return
	}
	defer f.Close()
	line := time.Now().Format(time.RFC3339) + " " + msg + "\n"
	if _, err := f.WriteString(line); err != nil {
		slog.Warn("audit log: scrittura fallita", "err", err)
	}
}
