package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func postConvert(t *testing.T, app *App, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/config-analyzer/convert", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, adminClaims))
	rec := httptest.NewRecorder()
	app.handleConfigAnalyzerConvert(rec, req)
	return rec
}

// Conversione da testo esplicito: 200, preview col commento del vendor di
// destinazione, e nessun source_text (che compare solo per il caso {ip}).
func TestConvertFromText(t *testing.T) {
	app, _ := testFGTApp(t)
	body := `{"source":"fortios","target":"panos","text":"config firewall address\n    edit \"A\"\n        set subnet 10.0.0.0 255.255.255.0\n    next\nend"}`
	rec := postConvert(t, app, body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody(t, rec)
	if _, ok := out["mapped"].([]any); !ok {
		t.Errorf("mapped assente: %#v", out["mapped"])
	}
	pt, _ := out["preview_text"].(string)
	if !strings.Contains(pt, "fortios -> panos") {
		t.Errorf("preview_text = %q", pt)
	}
	if _, ok := out["source_text"]; ok {
		t.Error("source_text presente per conversione da testo")
	}
}

// Vendor coincidenti o non firewall: 400 col messaggio del converter.
func TestConvertRejectsBadVendors(t *testing.T) {
	app, _ := testFGTApp(t)
	if rec := postConvert(t, app, `{"source":"fortios","target":"fortios","text":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("vendor coincidenti -> status %d, atteso 400", rec.Code)
	}
	if rec := postConvert(t, app, `{"source":"cisco","target":"panos","text":"x"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("vendor non firewall -> status %d, atteso 400", rec.Code)
	}
}

// Né text né ip: 400.
func TestConvertRequiresTextOrIP(t *testing.T) {
	app, _ := testFGTApp(t)
	rec := postConvert(t, app, `{"source":"fortios","target":"panos"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, atteso 400: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Fornire") {
		t.Errorf("messaggio = %q", rec.Body.String())
	}
}
