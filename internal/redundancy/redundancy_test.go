package redundancy

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRedundancyLifecycleAndParsers(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE redundancy_groups (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  group_name TEXT NOT NULL,
		  group_type TEXT NOT NULL,
		  name TEXT NOT NULL,
		  virtual_ip TEXT,
		  logical_device_ip TEXT,
		  health TEXT NOT NULL,
		  detection_source TEXT NOT NULL,
		  last_verified TEXT,
		  UNIQUE(group_name, group_type, name),
		  UNIQUE(logical_device_ip)
		);`,
		`CREATE TABLE redundancy_members (
		  id INTEGER PRIMARY KEY AUTOINCREMENT,
		  redundancy_group_id INTEGER NOT NULL REFERENCES redundancy_groups(id) ON DELETE CASCADE,
		  device_ip TEXT,
		  member_index INTEGER,
		  role TEXT NOT NULL,
		  serial TEXT,
		  norm_serial TEXT,
		  model TEXT,
		  firmware TEXT,
		  state TEXT NOT NULL,
		  mgmt_ip TEXT,
		  priority INTEGER,
		  details_json TEXT NOT NULL DEFAULT '{}'
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_members_group_norm_serial
		  ON redundancy_members(redundancy_group_id, norm_serial)
		  WHERE norm_serial IS NOT NULL;`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_members_group_index
		  ON redundancy_members(redundancy_group_id, member_index)
		  WHERE member_index IS NOT NULL;`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema stmt failed: %v", err)
		}
	}

	// 1. Test Cisco switch stack parse
	ciscoOutput := `
Switch/Stack Mac Address : 0011.2233.4400
                                           H/W   Current
Switch#   Role    Mac Address     Priority Version  State
------------------------------------------------------------
*1       Master   0011.2233.4400     15     V02     Ready               
 2       Standby  0011.2233.4401      1     V02     Ready               
 3       Member   0011.2233.4402      1     V02     Ready
`
	parsedStack := ParseCiscoSwitchStack(ciscoOutput, "T1", "10.0.0.10")
	if parsedStack == nil || len(parsedStack.Members) != 3 {
		t.Fatalf("expected 3 stack members, got %+v", parsedStack)
	}
	if parsedStack.Health != GroupHealthOK {
		t.Errorf("expected health ok, got %s", parsedStack.Health)
	}

	// 2. Save group
	id, err := SaveGroup(db, *parsedStack)
	if err != nil || id == 0 {
		t.Fatalf("SaveGroup failed: %v", err)
	}

	// 3. List groups
	groups, err := ListGroups(db, []string{"T1"})
	if err != nil || len(groups) != 1 {
		t.Fatalf("ListGroups failed: %v, got %d groups", err, len(groups))
	}
	if len(groups[0].Members) != 3 {
		t.Errorf("expected 3 members in retrieved group")
	}

	// 4. Get group
	g, err := GetGroup(db, id)
	if err != nil || g == nil {
		t.Fatalf("GetGroup failed: %v", err)
	}

	// 5. Delete group
	err = DeleteGroup(db, id)
	if err != nil {
		t.Fatalf("DeleteGroup failed: %v", err)
	}
	groups, _ = ListGroups(db, nil)
	if len(groups) != 0 {
		t.Errorf("expected 0 groups after delete")
	}
}
