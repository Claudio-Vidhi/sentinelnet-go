package store

import (
	"encoding/json"
	"time"
)

// TopologyRow: dati grezzi di topologia salvati dal triage per un apparato.
// neighbors/portchannels sono JSON (le struct vivono nel package topology).
type TopologyRow struct {
	IP               string
	Hostname         string
	VTPDomain        string
	VTPMode          string
	NeighborsJSON    string
	PortChannelsJSON string
	UpdatedAt        string
}

func (s *Store) UpsertTopology(ip, hostname, vtpDomain, vtpMode string, neighbors, portchannels any) error {
	nb, err := json.Marshal(neighbors)
	if err != nil {
		return err
	}
	pc, err := json.Marshal(portchannels)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT INTO topology_data(ip, hostname, vtp_domain, vtp_mode, neighbors_json, portchannels_json, updated_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, vtp_domain=excluded.vtp_domain,
			vtp_mode=excluded.vtp_mode, neighbors_json=excluded.neighbors_json,
			portchannels_json=excluded.portchannels_json, updated_at=excluded.updated_at`,
		ip, hostname, vtpDomain, vtpMode, string(nb), string(pc), time.Now().Format(time.RFC3339))
	return err
}

func (s *Store) ListTopology() ([]*TopologyRow, error) {
	rows, err := s.DB.Query(`SELECT ip, COALESCE(hostname,''), COALESCE(vtp_domain,''), COALESCE(vtp_mode,''),
		COALESCE(neighbors_json,'[]'), COALESCE(portchannels_json,'[]'), COALESCE(updated_at,'') FROM topology_data`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TopologyRow
	for rows.Next() {
		t := &TopologyRow{}
		if err := rows.Scan(&t.IP, &t.Hostname, &t.VTPDomain, &t.VTPMode, &t.NeighborsJSON, &t.PortChannelsJSON, &t.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ClearTopology azzera i dati topologici (reset mappa).
func (s *Store) ClearTopology() (int64, error) {
	res, err := s.DB.Exec(`DELETE FROM topology_data`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
