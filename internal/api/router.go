package api

import (
	"io/fs"
	"net/http"

	"github.com/Claudio-Vidhi/sentinelnet-go/web"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (a *App) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)

	// --- Statico / health (pub) ---
	r.Get("/", a.serveDashboard)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })

	// Heartbeat dell'interfaccia (pub): la sua assenza arresta il server quando
	// autoShutdown è attivo. GET e POST (fetch keepalive / sendBeacon).
	r.Get("/api/heartbeat", a.handleHeartbeat)
	r.Post("/api/heartbeat", a.handleHeartbeat)

	// --- Auth (pub) ---
	r.Get("/api/auth/status", a.handleAuthStatus)
	r.Post("/api/auth/register", a.handleRegister)
	r.Post("/api/auth/login", a.handleLogin)
	r.Post("/api/auth/change-password", a.requireAuth("", a.handleChangePassword))
	r.Get("/api/auth/me", a.requireAuth("", a.handleMe))

	// --- Users (adm) ---
	r.Get("/api/users", a.requireAuth("admin", a.handleListUsers))
	r.Post("/api/users", a.requireAuth("admin", a.handleCreateUser))
	r.Post("/api/users/delete", a.requireAuth("admin", a.handleDeleteUser))
	r.Post("/api/users/role", a.requireAuth("admin", a.handleUserRole))
	r.Post("/api/users/disable", a.requireAuth("admin", a.handleUserDisable))
	r.Post("/api/users/groups", a.requireAuth("admin", a.handleUserGroups))

	// --- Inventory (auth read / op write) ---
	r.Get("/api/local-devices", a.requireAuth("", a.handleLocalDevices))
	r.Get("/api/export/devices", a.requireAuth("", a.handleExportDevices))
	r.Post("/api/add-device", a.requireAuth("operator", a.handleAddDevice))
	r.Post("/api/delete-device", a.requireAuth("operator", a.handleDeleteDevice))
	r.Post("/api/rename-device", a.requireAuth("operator", a.handleRenameDevice))
	r.Post("/api/reassign-device", a.requireAuth("operator", a.handleReassignDevice))
	r.Post("/api/import-csv", a.requireAuth("operator", a.handleImportCSV))

	// --- Tenants/Groups ---
	r.Get("/api/groups", a.requireAuth("", a.handleListGroups))
	r.Post("/api/groups", a.requireAuth("operator", a.handleCreateGroup))
	r.Post("/api/groups/rename", a.requireAuth("operator", a.handleRenameGroup))
	r.Post("/api/groups/delete", a.requireAuth("operator", a.handleDeleteGroup))

	// --- Vendors / Models ---
	r.Get("/api/vendors", a.requireAuth("", a.handleListVendors))
	r.Post("/api/vendors", a.requireAuth("operator", a.handleAddVendor))
	r.Post("/api/vendors/delete", a.requireAuth("operator", a.handleDeleteVendor))
	r.Get("/api/models", a.requireAuth("", a.handleListModels))
	r.Post("/api/models", a.requireAuth("operator", a.handleAddModel))
	r.Post("/api/models/delete", a.requireAuth("operator", a.handleDeleteModel))

	// --- Classification ---
	r.Get("/api/device-classification", a.requireAuth("", a.handleClassification))
	r.Post("/api/device-categories", a.requireAuth("operator", a.handleCreateCategory))
	r.Post("/api/device-categories/delete", a.requireAuth("operator", a.handleDeleteCategory))
	r.Post("/api/device-categories/delete-subcategory", a.requireAuth("operator", a.handleDeleteSubcategory))
	r.Post("/api/device-categories/assign", a.requireAuth("operator", a.handleAssignCategory))
	r.Post("/api/promote-device", a.requireAuth("operator", a.handlePromoteDevice))

	// --- Topology ---
	r.Get("/api/topology", a.requireAuth("", a.handleTopology))
	r.Get("/api/network-map", a.requireAuth("", a.handleNetworkMap))
	r.Get("/api/portchannels", a.requireAuth("", a.handlePortchannels))
	r.Post("/api/topology/reset", a.requireAuth("operator", a.handleTopologyReset))

	// --- Triage / commands / ping ---
	r.Post("/api/send-command", a.requireAuth("operator", a.handleSendCommand))
	r.Post("/api/run-triage", a.requireAuth("operator", a.handleRunTriage))
	r.Post("/api/triage/{ip}", a.requireAuth("operator", a.handleTriageOne))
	r.Get("/api/triage-status", a.requireAuth("", a.handleTriageStatus))
	r.Post("/api/bulk-command", a.requireAuth("operator", a.handleBulkCommand))
	r.Get("/api/bulk-command/{job_id}", a.requireAuth("", a.handleJobStatus))
	r.Post("/api/ping-check", a.requireAuth("operator", a.handlePingCheck))
	r.Get("/api/ping/{ip}", a.requireAuth("operator", a.handlePingOne))
	r.Post("/api/scan-subnet", a.requireAuth("operator", a.handleScanSubnet))
	r.Get("/api/scan-subnet/{job_id}", a.requireAuth("", a.handleJobStatus))

	// --- Backup download ---
	r.Get("/api/download-backup/{name}", a.requireAuth("operator", a.handleDownloadBackup))

	// --- Threat intel EUVD ---
	r.Get("/api/search", a.requireAuth("", a.handleEUVDSearch))

	// --- MAC tracker ---
	r.Post("/api/mac/scan", a.requireAuth("operator", a.handleMacScan))
	r.Get("/api/mac/search", a.requireAuth("", a.handleMacSearch))
	r.Get("/api/mac/locate", a.requireAuth("", a.handleMacLocate))
	r.Get("/api/mac/stats", a.requireAuth("", a.handleMacStats))
	r.Post("/api/mac/settings", a.requireAuth("admin", a.handleMacSettings))
	r.Get("/api/mac/overrides", a.requireAuth("", a.handleMacOverrides))
	r.Post("/api/mac/overrides", a.requireAuth("operator", a.handleMacOverrideSave))
	r.Post("/api/mac/overrides/delete", a.requireAuth("operator", a.handleMacOverrideDelete))
	r.Get("/api/mac/switch/{ip}", a.requireAuth("", a.handleMacSwitchTable))

	// --- ARP / Client Map ---
	r.Post("/api/arp/scan", a.requireAuth("operator", a.handleARPScan))
	r.Get("/api/arp/search", a.requireAuth("", a.handleARPSearch))
	r.Get("/api/arp/client-map", a.requireAuth("", a.handleARPClientMap))
	r.Get("/api/arp/stats", a.requireAuth("", a.handleARPStats))

	// --- Observability (Live Flows) ---
	r.Get("/api/observability/top", a.requireAuth("", a.handleObsTop))
	r.Get("/api/observability/syslog", a.requireAuth("", a.handleObsSyslog))
	r.Get("/api/observability/anomalies", a.requireAuth("", a.handleObsAnomalies))
	r.Post("/api/observability/anomalies/{event_id}/status", a.requireAuth("operator", a.handleObsAnomalyStatus))
	r.Get("/api/observability/api-context", a.requireAuth("", a.handleObsAPIContext))
	r.Get("/api/observability/config", a.requireAuth("admin", a.handleObsGetConfig))
	r.Post("/api/observability/config", a.requireAuth("admin", a.handleObsSetConfig))
	r.Get("/api/observability/health", a.requireAuth("admin", a.handleObsHealth))

	// --- Config Analyzer (auth read, tenant-scoped) ---
	r.Get("/api/config-analyzer", a.requireAuth("", a.handleConfigAnalyzerAll))
	r.Get("/api/config-analyzer/{ip}", a.requireAuth("", a.handleConfigAnalyzerDevice))

	// --- Settings (adm) ---
	r.Get("/api/settings/network", a.requireAuth("admin", a.handleGetNetworkSettings))
	r.Post("/api/settings/network", a.requireAuth("admin", a.handleSetNetworkSettings))

	// --- WS terminal ---
	r.Post("/api/ws-token", a.requireAuth("operator", a.handleWSToken))
	r.Get("/api/ws-terminal/{ip}", a.handleWSTerminal) // auth via OTP nella query

	return r
}

func (a *App) serveDashboard(w http.ResponseWriter, r *http.Request) {
	data, err := fs.ReadFile(web.Files, "dashboard.html")
	if err != nil {
		http.Error(w, "dashboard non trovata", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}
