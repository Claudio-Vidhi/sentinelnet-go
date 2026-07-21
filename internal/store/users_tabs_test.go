package store

import "testing"

// Un utente appena creato non ha restrizioni: lista vuota, cioè tutte le tab.
func TestNewUserHasNoTabRestriction(t *testing.T) {
	st := testStore(t)
	if err := st.CreateUser("mario", "hash", "viewer", false); err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUser("mario")
	if err != nil || u == nil {
		t.Fatalf("utente non letto: %v", err)
	}
	if u.AllowedTabs == nil || len(u.AllowedTabs) != 0 {
		t.Errorf("allowed_tabs = %#v, attesa lista vuota", u.AllowedTabs)
	}
}

// Salvataggio e rilettura conservano l'ordine e il contenuto.
func TestSetAndGetAllowedTabs(t *testing.T) {
	st := testStore(t)
	if err := st.CreateUser("luigi", "hash", "operator", false); err != nil {
		t.Fatal(err)
	}
	ok, err := st.SetAllowedTabs("luigi", []string{"topology", "mac", "arp"})
	if err != nil || !ok {
		t.Fatalf("set fallito: ok=%v err=%v", ok, err)
	}
	u, _ := st.GetUser("luigi")
	if len(u.AllowedTabs) != 3 || u.AllowedTabs[0] != "topology" || u.AllowedTabs[2] != "arp" {
		t.Errorf("allowed_tabs = %#v", u.AllowedTabs)
	}

	// Anche ListUsers deve riportarle: la UI di gestione utenti le legge da lì.
	users, _ := st.ListUsers()
	var found *User
	for _, x := range users {
		if x.Username == "luigi" {
			found = x
		}
	}
	if found == nil || len(found.AllowedTabs) != 3 {
		t.Errorf("ListUsers non riporta le tab: %#v", found)
	}
}

// Una lista vuota rimuove ogni restrizione, senza cancellare l'utente.
func TestSetAllowedTabsEmptyClearsRestriction(t *testing.T) {
	st := testStore(t)
	if err := st.CreateUser("peach", "hash", "viewer", false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetAllowedTabs("peach", []string{"topology"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetAllowedTabs("peach", nil); err != nil {
		t.Fatal(err)
	}
	u, _ := st.GetUser("peach")
	if len(u.AllowedTabs) != 0 {
		t.Errorf("allowed_tabs = %#v, attesa vuota", u.AllowedTabs)
	}
}

// Impostare le tab di un utente inesistente non deve creare nulla, e lo
// segnala con false così l'handler può rispondere 404.
func TestSetAllowedTabsUnknownUser(t *testing.T) {
	st := testStore(t)
	ok, err := st.SetAllowedTabs("nessuno", []string{"topology"})
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("SetAllowedTabs ha riportato successo per un utente inesistente")
	}
}

// La colonna ha default '[]' dalla migrazione: un utente scritto prima che la
// colonna esistesse (simulato con un UPDATE a stringa vuota) non deve mandare
// in errore la lettura.
func TestDecodeTabsToleratesEmptyAndMalformed(t *testing.T) {
	st := testStore(t)
	if err := st.CreateUser("yoshi", "hash", "viewer", false); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "non-json", "null", "{}"} {
		if _, err := st.DB.Exec(`UPDATE users SET allowed_tabs = ? WHERE username = ?`, raw, "yoshi"); err != nil {
			t.Fatal(err)
		}
		u, err := st.GetUser("yoshi")
		if err != nil {
			t.Errorf("raw %q ha fatto fallire la lettura: %v", raw, err)
			continue
		}
		if u.AllowedTabs == nil || len(u.AllowedTabs) != 0 {
			t.Errorf("raw %q -> allowed_tabs = %#v, attesa vuota", raw, u.AllowedTabs)
		}
	}
}
