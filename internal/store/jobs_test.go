package store

import "testing"

func TestEnqueueAndGetJob(t *testing.T) {
	st := testStore(t)
	job, err := st.EnqueueJob("sede-a", "10.0.0.1", "show version", "operatore")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "pending" {
		t.Errorf("status = %q, atteso pending", job.Status)
	}
	if job.ID == "" || job.Created == 0 {
		t.Errorf("job incompleto: %+v", job)
	}

	again, err := st.GetJob(job.ID)
	if err != nil || again == nil {
		t.Fatalf("job non rileggibile: %v", err)
	}
	if again.Command != "show version" || again.RequestedBy != "operatore" {
		t.Errorf("job = %+v", again)
	}
	if missing, _ := st.GetJob("mai-esistito"); missing != nil {
		t.Error("job inesistente ritornato")
	}
}

// Il prelievo marca i job 'running': è ciò che impedisce che il polling
// successivo li restituisca di nuovo.
func TestClaimPendingJobsMarksRunning(t *testing.T) {
	st := testStore(t)
	for _, cmd := range []string{"show version", "show ip int brief"} {
		if _, err := st.EnqueueJob("sede-a", "10.0.0.1", cmd, "op"); err != nil {
			t.Fatal(err)
		}
	}

	jobs, err := st.ClaimPendingJobs("sede-a", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("job prelevati = %d, attesi 2", len(jobs))
	}
	for _, j := range jobs {
		if j.Status != "running" {
			t.Errorf("status = %q, atteso running", j.Status)
		}
	}

	// Un secondo polling non deve restituire di nuovo gli stessi comandi:
	// li eseguirebbe due volte sull'apparato.
	second, err := st.ClaimPendingJobs("sede-a", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Errorf("secondo polling = %d job, attesi 0", len(second))
	}
}

// Un agente vede solo i job della propria sede: il token con cui si autentica
// vale per quella e basta.
func TestClaimPendingJobsIsolatesSites(t *testing.T) {
	st := testStore(t)
	if _, err := st.EnqueueJob("sede-a", "10.0.0.1", "show version", "op"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnqueueJob("sede-b", "10.0.0.2", "show clock", "op"); err != nil {
		t.Fatal(err)
	}

	jobs, err := st.ClaimPendingJobs("sede-a", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 || jobs[0].SiteID != "sede-a" {
		t.Fatalf("job di un'altra sede prelevati: %+v", jobs)
	}
}

// I job più vecchi vengono prelevati per primi, e il limite è rispettato.
func TestClaimPendingJobsOrderAndLimit(t *testing.T) {
	st := testStore(t)
	for _, cmd := range []string{"primo", "secondo", "terzo"} {
		if _, err := st.EnqueueJob("sede-a", "10.0.0.1", cmd, "op"); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := st.ClaimPendingJobs("sede-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 2 {
		t.Fatalf("job = %d, attesi 2 per il limite", len(jobs))
	}
	if jobs[0].Command != "primo" {
		t.Errorf("primo job = %q, atteso il più vecchio", jobs[0].Command)
	}
}

func TestCompleteJob(t *testing.T) {
	st := testStore(t)
	job, _ := st.EnqueueJob("sede-a", "10.0.0.1", "show version", "op")

	ok, err := st.CompleteJob(job.ID, "sede-a", "done", "Cisco IOS ...")
	if err != nil || !ok {
		t.Fatalf("completamento fallito: ok=%v err=%v", ok, err)
	}
	again, _ := st.GetJob(job.ID)
	if again.Status != "done" || again.Result == "" {
		t.Errorf("job = %+v", again)
	}
}

// Un agente non deve poter chiudere il job di un'altra sede.
func TestCompleteJobRejectsForeignSite(t *testing.T) {
	st := testStore(t)
	job, _ := st.EnqueueJob("sede-a", "10.0.0.1", "show version", "op")

	ok, err := st.CompleteJob(job.ID, "sede-b", "done", "risultato falsificato")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("una sede ha chiuso il job di un'altra")
	}
	again, _ := st.GetJob(job.ID)
	if again.Result != "" || again.Status == "done" {
		t.Errorf("job alterato da un'altra sede: %+v", again)
	}
}

// Uno status inatteso non deve finire in tabella: si normalizza a 'done',
// come nel Python.
func TestCompleteJobNormalisesUnknownStatus(t *testing.T) {
	st := testStore(t)
	job, _ := st.EnqueueJob("sede-a", "10.0.0.1", "show version", "op")
	if _, err := st.CompleteJob(job.ID, "sede-a", "qualcosa-altro", "out"); err != nil {
		t.Fatal(err)
	}
	again, _ := st.GetJob(job.ID)
	if again.Status != "done" {
		t.Errorf("status = %q, atteso done", again.Status)
	}
}

func TestListJobs(t *testing.T) {
	st := testStore(t)
	st.EnqueueJob("sede-a", "10.0.0.1", "a", "op")
	st.EnqueueJob("sede-b", "10.0.0.2", "b", "op")

	all, err := st.ListJobs("", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("job totali = %d, attesi 2", len(all))
	}
	perSite, err := st.ListJobs("sede-a", 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(perSite) != 1 || perSite[0].SiteID != "sede-a" {
		t.Errorf("job della sede = %+v", perSite)
	}
}
