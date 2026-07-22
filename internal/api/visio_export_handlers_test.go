package api

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func visioApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	vault, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault)
}

func TestExportMapVSDX(t *testing.T) {
	app := visioApp(t)

	body := `{
		"nodes": [
			{"id": "10.0.0.1", "label": "SW1", "model": "C9300", "ip": "10.0.0.1", "x": 100, "y": 100},
			{"id": "10.0.0.2", "label": "SW2", "model": "C2960", "ip": "10.0.0.2", "x": 300, "y": 100}
		],
		"edges": [
			{"source": "10.0.0.1", "target": "10.0.0.2", "label": "Gi1/0/1", "color": "#6A5FC1"}
		]
	}`

	req := httptest.NewRequest("POST", "/api/map/export/vsdx", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "operator", Role: "operator"}))

	w := httptest.NewRecorder()
	app.handleExportMapVSDX(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d, body: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "application/vnd.ms-visio.drawing" {
		t.Errorf("unexpected Content-Type: %s", w.Header().Get("Content-Type"))
	}

	if !strings.Contains(w.Header().Get("Content-Disposition"), "attachment; filename=sentinelnet-map.vsdx") {
		t.Errorf("unexpected Content-Disposition: %s", w.Header().Get("Content-Disposition"))
	}

	// Verify readable zip file
	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatalf("invalid zip output: %v", err)
	}

	if len(zr.File) < 5 {
		t.Errorf("expected at least 5 files in vsdx zip, got %d", len(zr.File))
	}
}
