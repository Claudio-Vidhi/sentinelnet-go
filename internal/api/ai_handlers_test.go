package api

import (
	"encoding/base64"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB.Close() })
	key, _ := base64.StdEncoding.DecodeString(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	vault, err := crypto.NewVault(key)
	if err != nil {
		t.Fatal(err)
	}
	return NewApp(nil, st, nil, vault)
}

func TestProfilesEmptyByDefault(t *testing.T) {
	app := newTestApp(t)
	list, active := app.loadProfiles()
	if len(list) != 0 || active != "" {
		t.Fatalf("want empty list and no active, got %d profiles active=%q", len(list), active)
	}
}

func TestSaveLoadFindRoundtrip(t *testing.T) {
	app := newTestApp(t)
	p := aiProfile{ID: newProfileID(), Name: "p1", Provider: "ollama", APIKeyEnc: "secret-enc"}
	if err := app.saveProfiles([]aiProfile{p}, p.ID); err != nil {
		t.Fatal(err)
	}
	list, active := app.loadProfiles()
	if len(list) != 1 || active != p.ID {
		t.Fatalf("roundtrip mismatch: %d profiles active=%q", len(list), active)
	}
	if findProfile(list, p.ID) == nil {
		t.Error("findProfile should locate saved profile")
	}
	if findProfile(list, "nope") != nil || findProfile(list, "") != nil {
		t.Error("findProfile must return nil for missing/empty id")
	}
}

func TestMaskNeverExposesKey(t *testing.T) {
	m := maskProfile(aiProfile{ID: "x", Name: "n", Provider: "openai", APIKeyEnc: "ciphertext"})
	if _, ok := m["api_key_enc"]; ok {
		t.Error("mask must not include api_key_enc")
	}
	if _, ok := m["api_key"]; ok {
		t.Error("mask must not include api_key")
	}
	if m["api_key_set"] != true {
		t.Error("api_key_set should be true when key present")
	}
	if maskProfile(aiProfile{})["api_key_set"] != false {
		t.Error("api_key_set should be false when key absent")
	}
}
