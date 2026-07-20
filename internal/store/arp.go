package store

import (
	"database/sql"
	"strings"
	"time"
)

// ARPEntry è un binding MAC<->IP osservato sulla tabella ARP di un gateway L3.
type ARPEntry struct {
	ID         int64  `json:"id"`
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	VLAN       string `json:"vlan"`
	Interface  string `json:"interface"`
	SourceIP   string `json:"source_ip"`
	SourceName string `json:"source_name"`
	SourceType string `json:"source_type"`
	Tenant     string `json:"tenant"`
	Site       string `json:"site"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
	SeenCount  int    `json:"seen_count"`
}

// ARPInput è una riga grezza da registrare (output del parser).
type ARPInput struct {
	MAC       string
	IP        string
	VLAN      string
	Interface string
}

// ARPCounts riassume l'esito di una registrazione.
type ARPCounts struct {
	New     int `json:"new"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

const arpCols = `id, mac, ip, vlan, interface, source_ip, source_name, source_type,
	tenant, site, first_seen, last_seen, seen_count`

func scanARP(row interface{ Scan(...any) error }) (*ARPEntry, error) {
	e := &ARPEntry{}
	err := row.Scan(&e.ID, &e.MAC, &e.IP, &e.VLAN, &e.Interface, &e.SourceIP, &e.SourceName,
		&e.SourceType, &e.Tenant, &e.Site, &e.FirstSeen, &e.LastSeen, &e.SeenCount)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// normalizeMacStrict canonicalizza un MAC in "aa:bb:cc:dd:ee:ff", oppure
// ritorna ok=false se non sono esattamente 12 cifre esadecimali.
//
// Serve una variante severa perché mac.NormalizeMac ritorna comunque una
// stringa quando l'input non è valido, mentre qui occorre distinguere una
// ricerca esatta da una ricerca per frammento (come normalize_mac→None).
func normalizeMacStrict(raw string) (string, bool) {
	hex := hexOnly(raw)
	if len(hex) != 12 {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String(), true
}

func hexOnly(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RecordARPEntries registra (upsert) i binding letti da UN gateway L3.
// Chiave di upsert: (mac, ip, source_ip).
func (s *Store) RecordARPEntries(rows []ARPInput, sourceIP, sourceName, sourceType, tenant, site string) (ARPCounts, error) {
	var c ARPCounts
	if site == "" {
		site = "central"
	}
	now := time.Now().Format(time.RFC3339)

	tx, err := s.DB.Begin()
	if err != nil {
		return c, err
	}
	defer tx.Rollback()

	for _, r := range rows {
		mac, ok := normalizeMacStrict(r.MAC)
		ip := strings.TrimSpace(r.IP)
		if !ok || ip == "" {
			c.Skipped++
			continue
		}
		var id int64
		err := tx.QueryRow(`SELECT id FROM arp_entries WHERE mac=? AND ip=? AND source_ip=?`,
			mac, ip, sourceIP).Scan(&id)
		if err == nil {
			if _, err := tx.Exec(`UPDATE arp_entries
				SET last_seen=?, seen_count=seen_count+1, vlan=?, interface=?,
				    source_name=?, source_type=?, tenant=?, site=?
				WHERE id=?`,
				now, r.VLAN, strings.TrimSpace(r.Interface), sourceName, sourceType, tenant, site, id); err != nil {
				return c, err
			}
			c.Updated++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO arp_entries
			(mac, ip, vlan, interface, source_ip, source_name, source_type, tenant, site,
			 first_seen, last_seen, seen_count)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,1)`,
			mac, ip, r.VLAN, strings.TrimSpace(r.Interface), sourceIP, sourceName, sourceType,
			tenant, site, now, now); err != nil {
			return c, err
		}
		c.New++
	}
	return c, tx.Commit()
}

// SearchARP cerca i binding MAC<->IP. mac accetta anche frammenti/OUI.
// tenants: nil = nessuna restrizione (admin); slice vuota = nessun risultato.
func (s *Store) SearchARP(mac, ip, sourceIP string, tenants []string, limit int) ([]*ARPEntry, error) {
	if tenants != nil && len(tenants) == 0 {
		return []*ARPEntry{}, nil
	}
	q := strings.Builder{}
	q.WriteString(`SELECT ` + arpCols + ` FROM arp_entries WHERE 1=1`)
	var args []any

	if mac != "" {
		if norm, ok := normalizeMacStrict(mac); ok {
			q.WriteString(` AND mac = ?`)
			args = append(args, norm)
		} else if frag := hexOnly(mac); frag != "" {
			q.WriteString(` AND REPLACE(mac, ':', '') LIKE ?`)
			args = append(args, "%"+frag+"%")
		}
	}
	if ip != "" {
		q.WriteString(` AND ip LIKE ?`)
		args = append(args, ip+"%")
	}
	if sourceIP != "" {
		q.WriteString(` AND source_ip = ?`)
		args = append(args, sourceIP)
	}
	if tenants != nil {
		q.WriteString(` AND tenant IN (` + placeholders(len(tenants)) + `)`)
		for _, t := range tenants {
			args = append(args, t)
		}
	}
	q.WriteString(` ORDER BY last_seen DESC LIMIT ?`)
	args = append(args, clampLimit(limit))

	rows, err := s.DB.Query(q.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ARPEntry{}
	for rows.Next() {
		e, err := scanARP(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AccessPosition è l'ultima posizione fisica nota di un MAC (porta di accesso).
type AccessPosition struct {
	SwitchIP   string
	SwitchName string
	Interface  string
	VLAN       string
	LastSeen   string
}

// accessPositionsFor ritorna, per un insieme di MAC, l'avvistamento di accesso
// più recente per chiave (mac, tenant), escludendo gli uplink.
//
// La chiave INCLUDE il tenant di proposito: lo stesso MAC (o lo stesso IP
// RFC1918) può esistere in sedi diverse, e una join globale assocerebbe la
// posizione di un tenant al binding ARP di un altro — una fuga di dati fra
// tenant. Le query sono a chunk per restare sotto il limite di ~999 parametri
// di SQLite.
func (s *Store) accessPositionsFor(macs []string, tenants []string) (map[[2]string]AccessPosition, error) {
	best := map[[2]string]AccessPosition{}
	uniq := make([]string, 0, len(macs))
	seen := map[string]bool{}
	for _, m := range macs {
		if m != "" && !seen[m] {
			seen[m] = true
			uniq = append(uniq, m)
		}
	}
	if len(uniq) == 0 || (tenants != nil && len(tenants) == 0) {
		return best, nil
	}

	const chunk = 400
	for i := 0; i < len(uniq); i += chunk {
		end := i + chunk
		if end > len(uniq) {
			end = len(uniq)
		}
		batch := uniq[i:end]

		q := `SELECT mac, tenant, switch_ip, switch_name, interface, vlan, last_seen
		      FROM mac_sightings WHERE is_uplink = 0 AND mac IN (` + placeholders(len(batch)) + `)`
		args := make([]any, 0, len(batch)+len(tenants))
		for _, m := range batch {
			args = append(args, m)
		}
		if tenants != nil {
			q += ` AND tenant IN (` + placeholders(len(tenants)) + `)`
			for _, t := range tenants {
				args = append(args, t)
			}
		}
		q += ` ORDER BY last_seen DESC` // il primo per (mac, tenant) è il più recente

		rows, err := s.DB.Query(q, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var m, tenant string
			var p AccessPosition
			if err := rows.Scan(&m, &tenant, &p.SwitchIP, &p.SwitchName, &p.Interface, &p.VLAN, &p.LastSeen); err != nil {
				rows.Close()
				return nil, err
			}
			key := [2]string{m, tenant}
			if _, exists := best[key]; !exists {
				best[key] = p
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return best, nil
}

// ClientMapRow unisce il binding ARP alla posizione fisica di accesso.
type ClientMapRow struct {
	*ARPEntry
	ClientType   string `json:"client_type"`
	SwitchIP     string `json:"switch_ip"`
	SwitchName   string `json:"switch_name"`
	SwitchPort   string `json:"switch_port"`
	PortVLAN     string `json:"port_vlan"`
	PortLastSeen string `json:"port_last_seen"`
}

// ClientMap risponde a "che IP ha questo MAC e a quale porta è attaccato":
// binding ARP dei gateway arricchito con l'ultima posizione di accesso nota.
func (s *Store) ClientMap(mac, ip, sourceIP string, tenants []string, limit int) ([]*ClientMapRow, error) {
	entries, err := s.SearchARP(mac, ip, sourceIP, tenants, limit)
	if err != nil {
		return nil, err
	}
	macs := make([]string, 0, len(entries))
	for _, e := range entries {
		macs = append(macs, e.MAC)
	}
	best, err := s.accessPositionsFor(macs, tenants)
	if err != nil {
		return nil, err
	}
	// Il tipo di client è certo SOLO se assegnato a mano per IP; altrimenti
	// generico "client". Non si eredita mai source_type, che descrive il
	// gateway e non il client.
	meta, err := s.ListMeta()
	if err != nil {
		return nil, err
	}

	out := make([]*ClientMapRow, 0, len(entries))
	for _, e := range entries {
		row := &ClientMapRow{ARPEntry: e, ClientType: "client"}
		if m, ok := meta[e.IP]; ok && m.Category != "" {
			row.ClientType = m.Category
		}
		if p, ok := best[[2]string{e.MAC, e.Tenant}]; ok {
			row.SwitchIP, row.SwitchName = p.SwitchIP, p.SwitchName
			row.SwitchPort, row.PortVLAN, row.PortLastSeen = p.Interface, p.VLAN, p.LastSeen
		}
		out = append(out, row)
	}
	return out, nil
}

// ARPStats conta binding, MAC distinti e gateway di provenienza.
func (s *Store) ARPStats(tenants []string) (bindings, uniqueMacs, sources int, err error) {
	if tenants != nil && len(tenants) == 0 {
		return 0, 0, 0, nil
	}
	where := ""
	var args []any
	if tenants != nil {
		where = ` WHERE tenant IN (` + placeholders(len(tenants)) + `)`
		for _, t := range tenants {
			args = append(args, t)
		}
	}
	err = s.DB.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT mac), COUNT(DISTINCT source_ip)
		FROM arp_entries`+where, args...).Scan(&bindings, &uniqueMacs, &sources)
	return
}

// VlansForIPs ritorna { ip: vlan } dal binding ARP più recente con VLAN non
// vuota, VINCOLATO al tenant di ciascun IP (ipTenant: { ip: tenant }).
//
// Lo scoping per tenant è obbligatorio, non un'ottimizzazione: gli IP privati
// si ripetono su sedi diverse (RFC1918 dietro NAT indipendenti). Senza il
// filtro, un binding ARP della sede B comparirebbe nel grafo dei flussi della
// sede A solo perché condividono lo stesso indirizzo. Ogni lookup è quindi
// `ip = ? AND tenant = ?`, mai un IN(...) globale sugli IP.
//
// Gli IP senza binding noto per quel tenant sono assenti dal risultato: il
// fallback è lasciato al chiamante.
func (s *Store) VlansForIPs(ipTenant map[string]string) (map[string]string, error) {
	out := map[string]string{}
	if len(ipTenant) == 0 {
		return out, nil
	}
	for ip, tenant := range ipTenant {
		if ip == "" {
			continue
		}
		var vlan string
		err := s.DB.QueryRow(`SELECT vlan FROM arp_entries
			WHERE ip = ? AND tenant = ? AND vlan != ''
			ORDER BY last_seen DESC LIMIT 1`, ip, tenant).Scan(&vlan)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[ip] = vlan
	}
	return out, nil
}

// PruneARP elimina i binding più vecchi della retention.
func (s *Store) PruneARP(retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	res, err := s.DB.Exec(`DELETE FROM arp_entries WHERE last_seen < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func clampLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	if limit > 5000 {
		return 5000
	}
	return limit
}
