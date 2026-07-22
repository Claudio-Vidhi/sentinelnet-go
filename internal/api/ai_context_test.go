package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/config"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func mkCfg(dataDir string) *config.Config {
	return &config.Config{DataDir: dataDir}
}

func ctxAppWithDevices(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	must := func(e error) {
		if e != nil {
			t.Fatal(e)
		}
	}
	must(st.UpsertDevice(&store.Device{IP: "10.0.0.1", Hostname: "sw1", Vendor: "cisco", Tenant: "acme", Site: "central"}))
	must(st.UpsertDevice(&store.Device{IP: "10.0.0.2", Vendor: "hp", Tenant: "globex", Site: "central"}))
	return NewApp(nil, st, nil, nil)
}

func adminCtxReq(ip string) *http.Request {
	req := httptest.NewRequest("POST", "/", nil)
	return req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
}

func TestDeviceInventorySummaryScoping(t *testing.T) {
	app := ctxAppWithDevices(t)

	all := app.deviceInventorySummary(nil) // admin
	if !strings.Contains(all, "10.0.0.1") || !strings.Contains(all, "10.0.0.2") {
		t.Fatalf("admin summary should list both devices:\n%s", all)
	}
	if !strings.Contains(all, "(senza hostname)") {
		t.Errorf("device without hostname should show placeholder:\n%s", all)
	}

	acme := app.deviceInventorySummary([]string{"acme"})
	if !strings.Contains(acme, "10.0.0.1") || strings.Contains(acme, "10.0.0.2") {
		t.Fatalf("acme scope should only list acme device:\n%s", acme)
	}
}

func TestDeviceRunningConfigContextMissingBackup(t *testing.T) {
	app := ctxAppWithDevices(t)
	app.cfg = mkCfg(t.TempDir()) // empty backup dir
	w := httptest.NewRecorder()
	_, ok := app.deviceRunningConfigContext(w, adminCtxReq("10.0.0.1"), "10.0.0.1")
	if ok || w.Code != 404 {
		t.Fatalf("missing backup: ok=%v code=%d, want ok=false code=404", ok, w.Code)
	}
}

func TestDeviceRunningConfigContextUnknownDevice(t *testing.T) {
	app := ctxAppWithDevices(t)
	app.cfg = mkCfg(t.TempDir())
	w := httptest.NewRecorder()
	_, ok := app.deviceRunningConfigContext(w, adminCtxReq("9.9.9.9"), "9.9.9.9")
	if ok || w.Code != 404 {
		t.Fatalf("unknown device: ok=%v code=%d, want false/404", ok, w.Code)
	}
}
