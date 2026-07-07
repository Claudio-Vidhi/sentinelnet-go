package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func TestHandleSetNetworkSettingsValidation(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })

	app := NewApp(nil, st, nil, nil)

	post := func(host string) (*httptest.ResponseRecorder, map[string]any) {
		body := `{"host":"` + host + `"}`
		req := httptest.NewRequest("POST", "/api/settings/network", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
		rec := httptest.NewRecorder()
		app.handleSetNetworkSettings(rec, req)
		var resp map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return rec, resp
	}

	// Host non valido (non locale né 0.0.0.0/127.0.0.1) → 400.
	if rec, _ := post("203.0.113.5"); rec.Code != 400 {
		t.Errorf("host non valido: status = %d, want 400", rec.Code)
	}

	// 127.0.0.1 è sempre valido.
	rec, resp := post("127.0.0.1")
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if resp["status"] != "success" || resp["restart_required"] != true || resp["host"] != "127.0.0.1" {
		t.Errorf("risposta inattesa: %+v", resp)
	}
	if got := st.GetSetting(bindHostSettingKey, ""); got != "127.0.0.1" {
		t.Errorf("host persistito = %q, want 127.0.0.1", got)
	}

	// 0.0.0.0 è sempre valido.
	if rec, _ := post("0.0.0.0"); rec.Code != 200 {
		t.Errorf("0.0.0.0: status = %d", rec.Code)
	}
}

func TestResolveBindHostPrecedence(t *testing.T) {
	t.Setenv("SENTINELNET_HOST", "")
	getSetting := func(key, def string) string {
		if key == bindHostSettingKey {
			return "192.168.1.50"
		}
		return def
	}
	if got := resolveBindHost(getSetting); got != "192.168.1.50" {
		t.Errorf("senza env, atteso il valore persistito: got %q", got)
	}

	t.Setenv("SENTINELNET_HOST", "10.0.0.9")
	if got := resolveBindHost(getSetting); got != "10.0.0.9" {
		t.Errorf("env deve avere precedenza: got %q", got)
	}

	t.Setenv("SENTINELNET_HOST", "")
	if got := resolveBindHost(func(string, string) string { return "" }); got != "127.0.0.1" {
		t.Errorf("default atteso 127.0.0.1: got %q", got)
	}
}
