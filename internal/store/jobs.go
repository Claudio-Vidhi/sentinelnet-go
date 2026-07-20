package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"time"
)

// Coda dei job di comando: relay CLI dal centrale verso l'agente di sede.
// Il centrale accoda, l'agente preleva in polling, esegue in locale e riporta
// l'esito. Vive in tabella e non in memoria, così sopravvive ai riavvii.

// CommandJob è un comando accodato per una sede agent.
type CommandJob struct {
	ID          string  `json:"id"`
	SiteID      string  `json:"site_id"`
	DeviceIP    string  `json:"device_ip"`
	Command     string  `json:"command"`
	Status      string  `json:"status"`
	Result      string  `json:"result"`
	RequestedBy string  `json:"requested_by"`
	Created     float64 `json:"created"`
	Updated     float64 `json:"updated"`
}

const jobCols = `id, site_id, device_ip, command, status, result, requested_by, created, updated`

func scanJob(sc interface{ Scan(...any) error }) (*CommandJob, error) {
	j := &CommandJob{}
	err := sc.Scan(&j.ID, &j.SiteID, &j.DeviceIP, &j.Command, &j.Status,
		&j.Result, &j.RequestedBy, &j.Created, &j.Updated)
	return j, err
}

func newJobID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func nowFloat() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// EnqueueJob accoda un comando per una sede.
func (s *Store) EnqueueJob(siteID, deviceIP, command, requestedBy string) (*CommandJob, error) {
	id, err := newJobID()
	if err != nil {
		return nil, err
	}
	now := nowFloat()
	if _, err := s.DB.Exec(`INSERT INTO command_jobs(`+jobCols+`)
		VALUES(?,?,?,?, 'pending', '', ?,?,?)`,
		id, siteID, deviceIP, command, requestedBy, now, now); err != nil {
		return nil, err
	}
	return s.GetJob(id)
}

func (s *Store) GetJob(id string) (*CommandJob, error) {
	j, err := scanJob(s.DB.QueryRow(`SELECT `+jobCols+` FROM command_jobs WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// ClaimPendingJobs preleva i job pendenti di una sede marcandoli 'running'.
//
// Selezione e aggiornamento stanno in un'unica transazione: due agenti della
// stessa sede in polling contemporaneo eseguirebbero altrimenti lo stesso
// comando due volte, che su una CLI di apparato non è innocuo.
func (s *Store) ClaimPendingJobs(siteID string, limit int) ([]*CommandJob, error) {
	if limit <= 0 {
		limit = 20
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	rows, err := tx.Query(`SELECT `+jobCols+` FROM command_jobs
		WHERE site_id = ? AND status = 'pending' ORDER BY created ASC LIMIT ?`, siteID, limit)
	if err != nil {
		return nil, err
	}
	jobs := []*CommandJob{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	now := nowFloat()
	for _, j := range jobs {
		if _, err := tx.Exec(`UPDATE command_jobs SET status='running', updated=? WHERE id=?`,
			now, j.ID); err != nil {
			return nil, err
		}
		j.Status = "running"
		j.Updated = now
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return jobs, nil
}

// CompleteJob registra l'esito di un job.
//
// La condizione include site_id: un agente non deve poter chiudere il job di
// un'altra sede, e il token che lo autentica vale solo per la propria.
func (s *Store) CompleteJob(jobID, siteID, status, result string) (bool, error) {
	if status != "done" && status != "error" {
		status = "done"
	}
	res, err := s.DB.Exec(`UPDATE command_jobs SET status=?, result=?, updated=?
		WHERE id=? AND site_id=?`, status, result, nowFloat(), jobID, siteID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ListJobs elenca i job, opzionalmente di una sola sede.
func (s *Store) ListJobs(siteID string, limit int) ([]*CommandJob, error) {
	if limit <= 0 {
		limit = 100
	}
	var rows *sql.Rows
	var err error
	if siteID != "" {
		rows, err = s.DB.Query(`SELECT `+jobCols+` FROM command_jobs
			WHERE site_id = ? ORDER BY created DESC LIMIT ?`, siteID, limit)
	} else {
		rows, err = s.DB.Query(`SELECT `+jobCols+` FROM command_jobs
			ORDER BY created DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CommandJob{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}
