package api

import (
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/pingmon"
)

type pingMonitorConfigReq struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
}

// GET /api/settings/ping-monitor
func (a *App) handleGetPingMonitorSettings(w http.ResponseWriter, r *http.Request) {
	if a.pingMon == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false, "interval_seconds": 60})
		return
	}
	cfg := a.pingMon.GetConfig()
	writeJSON(w, http.StatusOK, cfg)
}

// POST /api/settings/ping-monitor
func (a *App) handleSetPingMonitorSettings(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	if a.pingMon == nil {
		writeErr(w, http.StatusInternalServerError, "Ping monitor non inizializzato.")
		return
	}

	var req pingMonitorConfigReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "Invalid JSON payload.")
		return
	}

	saved, err := a.pingMon.SaveConfig(req.Enabled, req.IntervalSeconds, claims.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "success",
		"enabled":          saved.Enabled,
		"interval_seconds": saved.IntervalSeconds,
	})
}

// GET /api/ping-monitor/status
func (a *App) handleGetPingMonitorStatus(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	allowedTenants, _ := a.tenantsForUser(claims.Username, claims.Role)

	if a.pingMon == nil {
		writeJSON(w, http.StatusOK, pingmon.StatusResponse{
			Enabled:         false,
			IntervalSeconds: 60,
			Devices:         []pingmon.DeviceState{},
			Summary:         pingmon.Summary{},
		})
		return
	}

	status := a.pingMon.GetStatus(allowedTenants)
	writeJSON(w, http.StatusOK, status)
}
