package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

// Un MAC collegato a SW-ACCESS (porta d'accesso) e visto in transito su SW-CORE
// (uplink verso SW-ACCESS): locate deve indicare SW-ACCESS come origine e
// SW-CORE come transito, con il vicino dell'uplink valorizzato.
func TestHandleMacLocateSplitsOriginAndTransit(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })

	mustSight := func(s *store.MacSighting) {
		if err := st.UpsertSighting(s); err != nil {
			t.Fatal(err)
		}
	}
	mac := "aa:bb:cc:dd:ee:ff"
	mustSight(&store.MacSighting{Mac: mac, Vlan: "10", SwitchIP: "10.0.0.2", SwitchName: "SW-ACCESS",
		Interface: "Gi1/0/5", IsUplink: false, Tenant: "Generale"})
	mustSight(&store.MacSighting{Mac: mac, Vlan: "10", SwitchIP: "10.0.0.1", SwitchName: "SW-CORE",
		Interface: "Po10", PortChannel: "Po10", IsUplink: true, UplinkTo: "SW-ACCESS", Tenant: "Generale"})

	app := NewApp(nil, st, nil, nil)

	req := httptest.NewRequest("GET", "/api/mac/locate?mac="+mac, nil)
	req = req.WithContext(context.WithValue(req.Context(), claimsKey, &auth.Claims{Username: "admin", Role: "admin"}))
	rec := httptest.NewRecorder()
	app.handleMacLocate(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Mac     string               `json:"mac"`
		Origin  []*store.MacSighting `json:"origin"`
		Transit []*store.MacSighting `json:"transit"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Origin) != 1 || resp.Origin[0].SwitchName != "SW-ACCESS" || resp.Origin[0].Interface != "Gi1/0/5" {
		t.Errorf("origine attesa SW-ACCESS/Gi1/0/5, trovata %+v", resp.Origin)
	}
	if len(resp.Transit) != 1 || resp.Transit[0].SwitchName != "SW-CORE" || resp.Transit[0].UplinkTo != "SW-ACCESS" {
		t.Errorf("transito atteso SW-CORE→SW-ACCESS, trovato %+v", resp.Transit)
	}
}
