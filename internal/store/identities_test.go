package store

import (
	"path/filepath"
	"testing"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/crypto"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_sentinelnet.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test store: %v", err)
	}
	t.Cleanup(func() { st.DB.Close() })
	return st
}

func TestIdentitiesStoreCRUD(t *testing.T) {
	st := openTestStore(t)

	// Create identity
	ident := &Identity{
		ID:          "id-123",
		Name:        "Default Cisco Creds",
		Tenant:      "acme",
		Username:    "admin",
		PasswordEnc: "enc_pass_123",
		SecretEnc:   "enc_secret_123",
	}

	if err := st.UpsertIdentity(ident); err != nil {
		t.Fatalf("UpsertIdentity failed: %v", err)
	}

	// Fetch single identity
	got, err := st.GetIdentity("id-123")
	if err != nil {
		t.Fatalf("GetIdentity failed: %v", err)
	}
	if got.Name != ident.Name || got.Username != ident.Username {
		t.Errorf("GetIdentity mismatch: got %+v, want %+v", got, ident)
	}

	// List identities with tenant filter
	list, err := st.ListIdentities("acme")
	if err != nil {
		t.Fatalf("ListIdentities failed: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListIdentities length mismatch: got %d, want 1", len(list))
	}
	if list[0].DevicesUsing != 0 {
		t.Errorf("expected DevicesUsing = 0, got %d", list[0].DevicesUsing)
	}

	// Associate a device with profile identity:id-123
	dev := &Device{
		IP:       "10.0.0.1",
		Vendor:   "cisco",
		Tenant:   "acme",
		Profile:  "identity:id-123",
		Username: "admin",
	}
	if err := st.UpsertDevice(dev); err != nil {
		t.Fatalf("UpsertDevice failed: %v", err)
	}

	// Check DevicesUsing count
	list, _ = st.ListIdentities("acme")
	if list[0].DevicesUsing != 1 {
		t.Errorf("expected DevicesUsing = 1, got %d", list[0].DevicesUsing)
	}

	// Delete blocked by devices using
	blocked, devices, err := st.DeleteIdentity("id-123")
	if err != nil {
		t.Fatalf("DeleteIdentity failed: %v", err)
	}
	if !blocked {
		t.Errorf("expected deletion to be blocked, but succeeded")
	}
	if len(devices) != 1 || devices[0] != "10.0.0.1" {
		t.Errorf("expected blocking devices [10.0.0.1], got %v", devices)
	}

	// Remove device and retry deletion
	_ = st.DeleteDevice("10.0.0.1")
	blocked, _, err = st.DeleteIdentity("id-123")
	if err != nil {
		t.Fatalf("DeleteIdentity failed after device removal: %v", err)
	}
	if blocked {
		t.Errorf("expected deletion to succeed after device removal")
	}

	// Verify deleted
	_, err = st.GetIdentity("id-123")
	if err == nil {
		t.Errorf("expected error fetching deleted identity, got nil")
	}
}

func TestGetIdentityCredentialsWithVault(t *testing.T) {
	st := openTestStore(t)
	v, err := crypto.NewVault(make([]byte, 32))
	if err != nil {
		t.Fatalf("failed creating vault: %v", err)
	}

	passEnc, _ := v.Encrypt("secretpass")
	secEnc, _ := v.Encrypt("enablepass")

	ident := &Identity{
		ID:          "id-456",
		Name:        "Encrypted Profile",
		Tenant:      "acme",
		Username:    "netadmin",
		PasswordEnc: passEnc,
		SecretEnc:   secEnc,
	}
	if err := st.UpsertIdentity(ident); err != nil {
		t.Fatalf("UpsertIdentity failed: %v", err)
	}

	creds, err := st.GetIdentityCredentials("id-456", v)
	if err != nil {
		t.Fatalf("GetIdentityCredentials failed: %v", err)
	}
	if creds.Username != "netadmin" || creds.Password != "secretpass" || creds.Secret != "enablepass" {
		t.Errorf("decrypted credentials mismatch: got %+v", creds)
	}
}
