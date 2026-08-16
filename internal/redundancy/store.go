package redundancy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// ListGroups elenca i gruppi di ridondanza, filtrati opzionalmente per tenant scope.
func ListGroups(db *sql.DB, scope []string) ([]GroupInfo, error) {
	q := `SELECT id, group_name, group_type, name, COALESCE(virtual_ip, ''), COALESCE(logical_device_ip, ''),
	             health, detection_source, COALESCE(last_verified, '')
	      FROM redundancy_groups WHERE 1=1`
	var args []any

	if scope != nil {
		if len(scope) == 0 {
			return []GroupInfo{}, nil
		}
		q += ` AND group_name IN (?` + strings.Repeat(",?", len(scope)-1) + `)`
		for _, s := range scope {
			args = append(args, s)
		}
	}
	q += ` ORDER BY id ASC`

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}

	var groups []GroupInfo
	for rows.Next() {
		var g GroupInfo
		if err := rows.Scan(&g.ID, &g.GroupName, &g.GroupType, &g.Name, &g.VirtualIP,
			&g.LogicalDeviceIP, &g.Health, &g.DetectionSource, &g.LastVerified); err != nil {
			continue
		}
		groups = append(groups, g)
	}
	rows.Close()

	for i := range groups {
		members, _ := getMembers(db, groups[i].ID)
		groups[i].Members = members
	}
	return groups, nil
}

// GetGroup ottiene un singolo gruppo per ID.
func GetGroup(db *sql.DB, groupID int64) (*GroupInfo, error) {
	var g GroupInfo
	err := db.QueryRow(
		`SELECT id, group_name, group_type, name, COALESCE(virtual_ip, ''), COALESCE(logical_device_ip, ''),
		        health, detection_source, COALESCE(last_verified, '')
		 FROM redundancy_groups WHERE id = ?`, groupID).
		Scan(&g.ID, &g.GroupName, &g.GroupType, &g.Name, &g.VirtualIP,
			&g.LogicalDeviceIP, &g.Health, &g.DetectionSource, &g.LastVerified)
	if err != nil {
		return nil, err
	}
	members, _ := getMembers(db, g.ID)
	g.Members = members
	return &g, nil
}

func getMembers(db *sql.DB, groupID int64) ([]MemberInfo, error) {
	rows, err := db.Query(
		`SELECT id, redundancy_group_id, COALESCE(device_ip, ''), member_index, role,
		        COALESCE(serial, ''), COALESCE(norm_serial, ''), COALESCE(model, ''),
		        COALESCE(firmware, ''), state, COALESCE(mgmt_ip, ''), priority, details_json
		 FROM redundancy_members WHERE redundancy_group_id = ?
		 ORDER BY member_index ASC, id ASC`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []MemberInfo
	for rows.Next() {
		var m MemberInfo
		var detailsJSON string
		var prio sql.NullInt64
		if err := rows.Scan(&m.ID, &m.RedundancyGroupID, &m.DeviceIP, &m.MemberIndex, &m.Role,
			&m.Serial, &m.NormSerial, &m.Model, &m.Firmware, &m.State, &m.MgmtIP, &prio, &detailsJSON); err != nil {
			continue
		}
		if prio.Valid {
			p := int(prio.Int64)
			m.Priority = &p
		}
		_ = json.Unmarshal([]byte(detailsJSON), &m.Details)
		members = append(members, m)
	}
	return members, nil
}

// SaveGroup inserisce o aggiorna un gruppo e i suoi membri in transazione.
func SaveGroup(db *sql.DB, g GroupInfo) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var groupID int64
	if g.ID > 0 {
		groupID = g.ID
		_, err := tx.Exec(
			`UPDATE redundancy_groups
			 SET group_name = ?, group_type = ?, name = ?, virtual_ip = ?,
			     logical_device_ip = ?, health = ?, detection_source = ?, last_verified = ?
			 WHERE id = ?`,
			g.GroupName, g.GroupType, g.Name, g.VirtualIP, g.LogicalDeviceIP,
			g.Health, g.DetectionSource, g.LastVerified, groupID)
		if err != nil {
			return 0, err
		}
		_, _ = tx.Exec(`DELETE FROM redundancy_members WHERE redundancy_group_id = ?`, groupID)
	} else {
		res, err := tx.Exec(
			`INSERT INTO redundancy_groups
			   (group_name, group_type, name, virtual_ip, logical_device_ip, health, detection_source, last_verified)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			g.GroupName, g.GroupType, g.Name, g.VirtualIP, g.LogicalDeviceIP,
			g.Health, g.DetectionSource, g.LastVerified)
		if err != nil {
			return 0, err
		}
		groupID, _ = res.LastInsertId()
	}

	for idx, m := range g.Members {
		detailsJSON, _ := json.Marshal(m.Details)
		normSerial := NormalizeSerial(m.Serial)
		var normSerialVal any
		if normSerial != "" {
			normSerialVal = normSerial
		}
		var serialVal any
		if m.Serial != "" {
			serialVal = m.Serial
		}

		memberIdx := m.MemberIndex
		if memberIdx == 0 {
			memberIdx = idx + 1
		}
		_, err := tx.Exec(
			`INSERT INTO redundancy_members
			   (redundancy_group_id, device_ip, member_index, role, serial, norm_serial, model, firmware, state, mgmt_ip, priority, details_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			groupID, m.DeviceIP, memberIdx, m.Role, serialVal, normSerialVal, m.Model,
			m.Firmware, m.State, m.MgmtIP, m.Priority, string(detailsJSON))
		if err != nil {
			return 0, fmt.Errorf("inserimento membro %d fallito: %w", idx, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return groupID, nil
}

// DeleteGroup rimuove un gruppo e i membri associati.
func DeleteGroup(db *sql.DB, groupID int64) error {
	_, err := db.Exec(`DELETE FROM redundancy_groups WHERE id = ?`, groupID)
	return err
}
