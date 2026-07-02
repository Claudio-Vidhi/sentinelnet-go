package store

import "database/sql"

type Category struct {
	Key           string   `json:"-"`
	Label         string   `json:"label"`
	Builtin       bool     `json:"builtin"`
	Subcategories []string `json:"subcategories"`
}

type DeviceMeta struct {
	NodeID      string
	Category    string
	Subcategory string
	Vendor      string
	Model       string
	HAGroup     string
	Name        string
	Ver         string
}

func (s *Store) ListCategories() (map[string]*Category, error) {
	rows, err := s.DB.Query(`SELECT key, COALESCE(label,''), builtin FROM categories ORDER BY builtin DESC, key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*Category{}
	for rows.Next() {
		c := &Category{Subcategories: []string{}}
		var builtin int
		if err := rows.Scan(&c.Key, &c.Label, &builtin); err != nil {
			return nil, err
		}
		c.Builtin = builtin != 0
		out[c.Key] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	subs, err := s.DB.Query(`SELECT category, name FROM subcategories ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer subs.Close()
	for subs.Next() {
		var cat, name string
		if err := subs.Scan(&cat, &name); err != nil {
			return nil, err
		}
		if c, ok := out[cat]; ok {
			c.Subcategories = append(c.Subcategories, name)
		}
	}
	return out, subs.Err()
}

func (s *Store) CreateCategory(key, label string) error {
	if label == "" {
		label = key
	}
	_, err := s.DB.Exec(`INSERT OR IGNORE INTO categories(key, label, builtin) VALUES(?, ?, 0)`, key, label)
	return err
}

func (s *Store) DeleteCategory(key string) error {
	var builtin int
	err := s.DB.QueryRow(`SELECT builtin FROM categories WHERE key = ?`, key).Scan(&builtin)
	if err != nil {
		return err
	}
	if builtin != 0 {
		return errBuiltinCategory
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM subcategories WHERE category = ?`, key); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE device_meta SET category = '', subcategory = '' WHERE category = ?`, key); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM categories WHERE key = ?`, key); err != nil {
		return err
	}
	return tx.Commit()
}

var errBuiltinCategory = errString("categoria di sistema non eliminabile")

type errString string

func (e errString) Error() string { return string(e) }

func (s *Store) AddSubcategory(category, name string) error {
	_, err := s.DB.Exec(`INSERT OR IGNORE INTO subcategories(category, name) VALUES(?, ?)`, category, name)
	return err
}

func (s *Store) DeleteSubcategory(category, name string) error {
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE device_meta SET subcategory = '' WHERE category = ? AND subcategory = ?`, category, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM subcategories WHERE category = ? AND name = ?`, category, name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) GetMeta(nodeID string) (*DeviceMeta, error) {
	m := &DeviceMeta{}
	err := s.DB.QueryRow(`SELECT node_id, COALESCE(category,''), COALESCE(subcategory,''), COALESCE(vendor,''),
		COALESCE(model,''), COALESCE(ha_group,''), COALESCE(name,''), COALESCE(ver,'')
		FROM device_meta WHERE node_id = ?`, nodeID).
		Scan(&m.NodeID, &m.Category, &m.Subcategory, &m.Vendor, &m.Model, &m.HAGroup, &m.Name, &m.Ver)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return m, err
}

func (s *Store) ListMeta() (map[string]*DeviceMeta, error) {
	rows, err := s.DB.Query(`SELECT node_id, COALESCE(category,''), COALESCE(subcategory,''), COALESCE(vendor,''),
		COALESCE(model,''), COALESCE(ha_group,''), COALESCE(name,''), COALESCE(ver,'') FROM device_meta`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]*DeviceMeta{}
	for rows.Next() {
		m := &DeviceMeta{}
		if err := rows.Scan(&m.NodeID, &m.Category, &m.Subcategory, &m.Vendor, &m.Model, &m.HAGroup, &m.Name, &m.Ver); err != nil {
			return nil, err
		}
		out[m.NodeID] = m
	}
	return out, rows.Err()
}

// AssignMeta aggiorna solo i campi presenti in fields (patch parziale).
func (s *Store) AssignMeta(nodeID string, fields map[string]string) error {
	existing, err := s.GetMeta(nodeID)
	if err != nil {
		return err
	}
	if existing == nil {
		existing = &DeviceMeta{NodeID: nodeID}
	}
	apply := func(dst *string, key string) {
		if v, ok := fields[key]; ok {
			*dst = v
		}
	}
	apply(&existing.Category, "category")
	apply(&existing.Subcategory, "subcategory")
	apply(&existing.Vendor, "vendor")
	apply(&existing.Model, "model")
	apply(&existing.HAGroup, "ha_group")
	apply(&existing.Name, "name")
	apply(&existing.Ver, "version")
	_, err = s.DB.Exec(`INSERT INTO device_meta(node_id, category, subcategory, vendor, model, ha_group, name, ver)
		VALUES(?,?,?,?,?,?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET category=excluded.category, subcategory=excluded.subcategory,
			vendor=excluded.vendor, model=excluded.model, ha_group=excluded.ha_group,
			name=excluded.name, ver=excluded.ver`,
		existing.NodeID, existing.Category, existing.Subcategory, existing.Vendor,
		existing.Model, existing.HAGroup, existing.Name, existing.Ver)
	return err
}
