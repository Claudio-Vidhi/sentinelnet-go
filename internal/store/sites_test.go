package store

import (
	"strings"
	"testing"
)

// testStore è definita in arp_test.go.

// La sede 'central' esiste dalla migrazione: senza, l'inventario non avrebbe
// una sede a cui attribuire i dispositivi già presenti.
func TestDefaultSiteExists(t *testing.T) {
	st := testStore(t)
	site, err := st.GetSite(DefaultSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if site == nil {
		t.Fatal("la sede 'central' non esiste dopo la migrazione")
	}
	if site.Mode != ModeCentral || site.HasToken {
		t.Errorf("sede central inattesa: %+v", site)
	}
}

// Una sede agent riceve un token in chiaro una sola volta; su disco resta solo
// l'hash, e il token non è più recuperabile da nessuna API.
func TestCreateAgentSiteReturnsTokenOnlyOnce(t *testing.T) {
	st := testStore(t)
	site, token, err := st.CreateSite("Sede Milano", ModeAgent, []string{"10.1.0.0/24", "  ", ""})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("nessun token per una sede agent")
	}
	if site.ID != "sede-milano" {
		t.Errorf("id = %q, atteso lo slug del nome", site.ID)
	}
	if len(site.Subnets) != 1 || site.Subnets[0] != "10.1.0.0/24" {
		t.Errorf("subnets = %#v, attese le sole voci non vuote", site.Subnets)
	}
	if !site.HasToken {
		t.Error("has_token falso su una sede con token")
	}

	// Riletta dal database non deve esporre il token in nessuna forma.
	again, err := st.GetSite(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(again.tokenHash, token) || again.tokenHash == token {
		t.Error("il token è memorizzato in chiaro")
	}
	if len(again.tokenHash) != 64 {
		t.Errorf("token_hash = %q, atteso uno SHA-256 esadecimale", again.tokenHash)
	}
}

// Una sede central non ha token: non c'è nessun agente che debba autenticarsi.
func TestCreateCentralSiteHasNoToken(t *testing.T) {
	st := testStore(t)
	site, token, err := st.CreateSite("Sede Roma", ModeCentral, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" || site.HasToken {
		t.Error("token generato per una sede central")
	}
}

func TestCreateSiteRejectsEmptyNameAndBadMode(t *testing.T) {
	st := testStore(t)
	if _, _, err := st.CreateSite("  ", ModeAgent, nil); err == nil {
		t.Error("nome vuoto accettato")
	}
	if _, _, err := st.CreateSite("X", "remoto", nil); err == nil {
		t.Error("modalità non valida accettata")
	}
}

// Due sedi con lo stesso nome non devono collidere sull'id.
func TestCreateSiteDisambiguatesDuplicateNames(t *testing.T) {
	st := testStore(t)
	a, _, err := st.CreateSite("Filiale", ModeCentral, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := st.CreateSite("Filiale", ModeCentral, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID {
		t.Fatalf("id duplicato: %q", a.ID)
	}
	if !strings.HasPrefix(b.ID, "filiale-") {
		t.Errorf("id = %q, atteso il prefisso dello slug", b.ID)
	}
}

// L'autenticazione riconosce il token giusto e rifiuta tutto il resto.
func TestAuthenticateSite(t *testing.T) {
	st := testStore(t)
	site, token, err := st.CreateSite("Sede Agente", ModeAgent, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := st.AuthenticateSite(token)
	if err != nil {
		t.Fatal(err)
	}
	if got != site.ID {
		t.Errorf("autenticazione = %q, attesa %q", got, site.ID)
	}
	for _, bad := range []string{"", "token-sbagliato", token + "x", strings.ToUpper(token)} {
		if got, _ := st.AuthenticateSite(bad); got != "" {
			t.Errorf("token %q accettato come sede %q", bad, got)
		}
	}
}

// Una sede central non è autenticabile nemmeno se in passato aveva un token:
// il passaggio a central lo azzera.
func TestSwitchingToCentralInvalidatesToken(t *testing.T) {
	st := testStore(t)
	site, token, err := st.CreateSite("Sede Mista", ModeAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	mode := ModeCentral
	if ok, err := st.UpdateSite(site.ID, nil, &mode, nil); err != nil || !ok {
		t.Fatalf("update fallito: %v", err)
	}
	if got, _ := st.AuthenticateSite(token); got != "" {
		t.Error("il token continua a funzionare dopo il passaggio a central")
	}
	again, _ := st.GetSite(site.ID)
	if again.HasToken {
		t.Error("has_token ancora vero dopo il passaggio a central")
	}
}

// La rigenerazione invalida il token precedente: è il suo scopo.
func TestRegenerateSiteTokenInvalidatesOld(t *testing.T) {
	st := testStore(t)
	site, old, err := st.CreateSite("Sede Rig", ModeAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := st.RegenerateSiteToken(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == "" || fresh == old {
		t.Fatalf("token rigenerato = %q (vecchio %q)", fresh, old)
	}
	if got, _ := st.AuthenticateSite(old); got != "" {
		t.Error("il token vecchio è ancora valido")
	}
	if got, _ := st.AuthenticateSite(fresh); got != site.ID {
		t.Error("il token nuovo non autentica")
	}
}

// Rigenerare su una sede central non ha senso e non deve inventare un token.
func TestRegenerateTokenOnlyForAgentSites(t *testing.T) {
	st := testStore(t)
	if tok, _ := st.RegenerateSiteToken(DefaultSiteID); tok != "" {
		t.Error("token generato per la sede central")
	}
	if tok, _ := st.RegenerateSiteToken("inesistente"); tok != "" {
		t.Error("token generato per una sede inesistente")
	}
}

// La sede di default non è eliminabile: è quella a cui è attribuito tutto
// l'inventario che non appartiene a una sede remota.
func TestDeleteSiteProtectsDefault(t *testing.T) {
	st := testStore(t)
	if ok, _ := st.DeleteSite(DefaultSiteID); ok {
		t.Error("la sede central è stata eliminata")
	}
	if site, _ := st.GetSite(DefaultSiteID); site == nil {
		t.Error("la sede central non esiste più")
	}

	s, _, _ := st.CreateSite("Sede Temp", ModeCentral, nil)
	if ok, err := st.DeleteSite(s.ID); err != nil || !ok {
		t.Fatalf("sede normale non eliminata: %v", err)
	}
	if ok, _ := st.DeleteSite("mai-esistita"); ok {
		t.Error("eliminata una sede inesistente")
	}
}

func TestTouchSiteLastSeen(t *testing.T) {
	st := testStore(t)
	site, _, _ := st.CreateSite("Sede LS", ModeAgent, nil)
	if site.LastSeen != nil {
		t.Error("last_seen valorizzato su una sede appena creata")
	}
	if err := st.TouchSiteLastSeen(site.ID); err != nil {
		t.Fatal(err)
	}
	again, _ := st.GetSite(site.ID)
	if again.LastSeen == nil || *again.LastSeen <= 0 {
		t.Errorf("last_seen = %v", again.LastSeen)
	}
}
