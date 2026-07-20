package store

import "testing"

func TestFortiGateTargetCRUD(t *testing.T) {
	s := testStore(t)

	if err := s.UpsertFortiGateTarget(&FortiGateTarget{
		IP: "10.0.0.1", Name: "Sede", VerifyTLS: true, TokenEnc: "cifrato-1",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetFortiGateTarget("10.0.0.1")
	if err != nil || got == nil {
		t.Fatalf("target non trovato: %v", err)
	}
	if got.Port != 443 {
		t.Errorf("porta = %d, atteso il default 443", got.Port)
	}
	if got.Name != "Sede" || !got.VerifyTLS || got.TokenEnc != "cifrato-1" {
		t.Errorf("target = %+v", got)
	}

	if missing, err := s.GetFortiGateTarget("10.9.9.9"); err != nil || missing != nil {
		t.Errorf("target inesistente = %+v (err %v), atteso nil", missing, err)
	}

	if err := s.DeleteFortiGateTarget("10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetFortiGateTarget("10.0.0.1"); got != nil {
		t.Error("target non eliminato")
	}
}

// Un token vuoto non deve cancellare quello salvato: la UI mostra
// "•••• invariato" e rinominare un target non deve costringere a reinserirlo.
func TestUpsertFortiGateTargetKeepsTokenWhenEmpty(t *testing.T) {
	s := testStore(t)
	if err := s.UpsertFortiGateTarget(&FortiGateTarget{
		IP: "10.0.0.1", Name: "Prima", Port: 8443, TokenEnc: "cifrato-1",
	}); err != nil {
		t.Fatal(err)
	}
	// Rinomina senza token.
	if err := s.UpsertFortiGateTarget(&FortiGateTarget{
		IP: "10.0.0.1", Name: "Dopo", Port: 8443,
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetFortiGateTarget("10.0.0.1")
	if got.Name != "Dopo" {
		t.Errorf("nome = %q, atteso Dopo", got.Name)
	}
	if got.TokenEnc != "cifrato-1" {
		t.Errorf("token = %q, doveva restare invariato", got.TokenEnc)
	}

	// Un token valorizzato invece sostituisce.
	if err := s.UpsertFortiGateTarget(&FortiGateTarget{
		IP: "10.0.0.1", Name: "Dopo", TokenEnc: "cifrato-2",
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ = s.GetFortiGateTarget("10.0.0.1"); got.TokenEnc != "cifrato-2" {
		t.Errorf("token = %q, atteso cifrato-2", got.TokenEnc)
	}
}

// Un solo target può essere attivo.
func TestOnlyOneActiveFortiGateTarget(t *testing.T) {
	s := testStore(t)
	for _, ip := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if err := s.UpsertFortiGateTarget(&FortiGateTarget{IP: ip, TokenEnc: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if active, _ := s.ActiveFortiGateTarget(); active != nil {
		t.Errorf("attivo = %+v, atteso nessuno all'inizio", active)
	}

	if err := s.SetActiveFortiGateTarget("10.0.0.2"); err != nil {
		t.Fatal(err)
	}
	active, err := s.ActiveFortiGateTarget()
	if err != nil || active == nil || active.IP != "10.0.0.2" {
		t.Fatalf("attivo = %+v (err %v)", active, err)
	}

	// Cambiando target il precedente deve essere disattivato.
	if err := s.SetActiveFortiGateTarget("10.0.0.3"); err != nil {
		t.Fatal(err)
	}
	targets, _ := s.ListFortiGateTargets()
	activeCount := 0
	for _, tg := range targets {
		if tg.Active {
			activeCount++
			if tg.IP != "10.0.0.3" {
				t.Errorf("attivo sbagliato: %s", tg.IP)
			}
		}
	}
	if activeCount != 1 {
		t.Errorf("target attivi = %d, atteso 1", activeCount)
	}
}

func TestListFortiGateTargetsOrdered(t *testing.T) {
	s := testStore(t)
	for _, ip := range []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"} {
		if err := s.UpsertFortiGateTarget(&FortiGateTarget{IP: ip}); err != nil {
			t.Fatal(err)
		}
	}
	targets, err := s.ListFortiGateTargets()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 3 {
		t.Fatalf("target = %d, attesi 3", len(targets))
	}
	if targets[0].IP != "10.0.0.1" || targets[2].IP != "10.0.0.3" {
		t.Errorf("ordine inatteso: %s, %s, %s", targets[0].IP, targets[1].IP, targets[2].IP)
	}
}
