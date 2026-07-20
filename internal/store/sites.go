package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Sedi multi-sito. Ogni sede ha una modalità:
//   - "central": il SentinelNet centrale raggiunge i dispositivi remoti
//     direttamente via VPN, senza processi remoti;
//   - "agent":   un agente leggero gira nella sede, si connette IN USCITA verso
//     il centrale e riceve i comandi da una coda di job.

const (
	// DefaultSiteID è la sede sempre presente e non eliminabile.
	DefaultSiteID = "central"
	ModeCentral   = "central"
	ModeAgent     = "agent"
)

// Site è una sede. TokenHash non esce mai dal package: le API espongono
// HasToken, perché il token non è recuperabile per costruzione.
type Site struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Mode     string   `json:"mode"`
	Subnets  []string `json:"subnets"`
	Created  float64  `json:"created"`
	LastSeen *float64 `json:"last_seen"`
	HasToken bool     `json:"has_token"`

	tokenHash string
}

// hashToken riduce un token al suo SHA-256 esadecimale.
//
// È un hash, non una cifratura: il token di sede non deve essere recuperabile
// nemmeno da chi ha la chiave del vault. Viene mostrato una volta alla
// creazione e da quel momento si può solo verificare.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newToken genera un token di sede: 32 byte casuali in base64url, come
// secrets.token_urlsafe(32) del Python.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var reNonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// slugify deriva l'id dal nome della sede.
func slugify(name string) string {
	s := reNonSlug.ReplaceAllString(strings.ToLower(strings.TrimSpace(name)), "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "site"
	}
	return s
}

func scanSite(sc interface{ Scan(...any) error }) (*Site, error) {
	s := &Site{}
	var subnets string
	var lastSeen sql.NullFloat64
	if err := sc.Scan(&s.ID, &s.Name, &s.Mode, &subnets, &s.tokenHash, &s.Created, &lastSeen); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(subnets), &s.Subnets); err != nil || s.Subnets == nil {
		s.Subnets = []string{}
	}
	if lastSeen.Valid {
		v := lastSeen.Float64
		s.LastSeen = &v
	}
	s.HasToken = s.tokenHash != ""
	return s, nil
}

const siteCols = `id, name, mode, subnets, token_hash, created, last_seen`

func (s *Store) ListSites() ([]*Site, error) {
	rows, err := s.DB.Query(`SELECT ` + siteCols + ` FROM sites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Site{}
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func (s *Store) GetSite(id string) (*Site, error) {
	site, err := scanSite(s.DB.QueryRow(`SELECT `+siteCols+` FROM sites WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return site, err
}

// cleanSubnets scarta le voci vuote, come il Python.
func cleanSubnets(in []string) []string {
	out := []string{}
	for _, v := range in {
		if t := strings.TrimSpace(v); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// CreateSite crea una sede e, se è in modalità agent, ne genera il token.
// Il token in chiaro è ritornato UNA SOLA VOLTA: su disco resta solo l'hash.
func (s *Store) CreateSite(name, mode string, subnets []string) (*Site, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("il nome della sede è obbligatorio")
	}
	if mode != ModeCentral && mode != ModeAgent {
		return nil, "", fmt.Errorf("modalità non valida: %s", mode)
	}

	// L'id deriva dal nome; in caso di collisione si aggiunge un suffisso
	// casuale invece di rifiutare la creazione.
	base := slugify(name)
	id := base
	for i := 0; ; i++ {
		existing, err := s.GetSite(id)
		if err != nil {
			return nil, "", err
		}
		if existing == nil {
			break
		}
		suffix, err := newToken()
		if err != nil {
			return nil, "", err
		}
		id = base + "-" + strings.ToLower(suffix[:4])
		if i > 8 {
			return nil, "", fmt.Errorf("impossibile generare un id univoco per '%s'", name)
		}
	}

	var tokenPlain, tokenHash string
	if mode == ModeAgent {
		var err error
		if tokenPlain, err = newToken(); err != nil {
			return nil, "", err
		}
		tokenHash = hashToken(tokenPlain)
	}

	subnetsJSON, err := json.Marshal(cleanSubnets(subnets))
	if err != nil {
		return nil, "", err
	}
	if _, err := s.DB.Exec(
		`INSERT INTO sites(id, name, mode, subnets, token_hash, created) VALUES(?,?,?,?,?,?)`,
		id, name, mode, string(subnetsJSON), tokenHash, float64(time.Now().UnixNano())/1e9,
	); err != nil {
		return nil, "", err
	}
	site, err := s.GetSite(id)
	return site, tokenPlain, err
}

// UpdateSite aggiorna i campi indicati (nil = invariato). Ritorna false se la
// sede non esiste.
func (s *Store) UpdateSite(id string, name, mode *string, subnets *[]string) (bool, error) {
	site, err := s.GetSite(id)
	if err != nil || site == nil {
		return false, err
	}
	if name != nil && strings.TrimSpace(*name) != "" {
		site.Name = strings.TrimSpace(*name)
	}
	if mode != nil {
		if *mode != ModeCentral && *mode != ModeAgent {
			return false, fmt.Errorf("modalità non valida: %s", *mode)
		}
		site.Mode = *mode
		// Passando a 'central' il token non serve più, e lasciarlo in tabella
		// vorrebbe dire tenere valida una credenziale che nessuno userà.
		if *mode == ModeCentral {
			site.tokenHash = ""
		}
	}
	if subnets != nil {
		site.Subnets = cleanSubnets(*subnets)
	}

	subnetsJSON, err := json.Marshal(site.Subnets)
	if err != nil {
		return false, err
	}
	_, err = s.DB.Exec(`UPDATE sites SET name=?, mode=?, subnets=?, token_hash=? WHERE id=?`,
		site.Name, site.Mode, string(subnetsJSON), site.tokenHash, id)
	return err == nil, err
}

// DeleteSite elimina una sede. La sede di default non è eliminabile.
func (s *Store) DeleteSite(id string) (bool, error) {
	if id == DefaultSiteID {
		return false, nil
	}
	res, err := s.DB.Exec(`DELETE FROM sites WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RegenerateSiteToken rigenera il token di una sede agent e ne ritorna il
// valore in chiaro. Stringa vuota se la sede non esiste o non è in modalità
// agent: solo quelle hanno un token da usare.
func (s *Store) RegenerateSiteToken(id string) (string, error) {
	site, err := s.GetSite(id)
	if err != nil || site == nil || site.Mode != ModeAgent {
		return "", err
	}
	token, err := newToken()
	if err != nil {
		return "", err
	}
	if _, err := s.DB.Exec(`UPDATE sites SET token_hash=? WHERE id=?`, hashToken(token), id); err != nil {
		return "", err
	}
	return token, nil
}

// TouchSiteLastSeen registra il momento in cui l'agente si è fatto vivo.
func (s *Store) TouchSiteLastSeen(id string) error {
	_, err := s.DB.Exec(`UPDATE sites SET last_seen=? WHERE id=?`,
		float64(time.Now().UnixNano())/1e9, id)
	return err
}

// AuthenticateSite ritorna l'id della sede agent il cui token corrisponde,
// oppure stringa vuota.
//
// Il confronto è a tempo costante: un confronto normale su stringhe esce al
// primo byte diverso, e la differenza di tempo è misurabile da chi prova
// token a ripetizione.
func (s *Store) AuthenticateSite(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	want := []byte(hashToken(token))

	sites, err := s.ListSites()
	if err != nil {
		return "", err
	}
	found := ""
	for _, site := range sites {
		if site.Mode != ModeAgent || site.tokenHash == "" {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(site.tokenHash), want) == 1 {
			found = site.ID
			// Nessun break: uscire al primo riscontro renderebbe il tempo di
			// risposta dipendente dalla posizione della sede in elenco.
		}
	}
	return found, nil
}
