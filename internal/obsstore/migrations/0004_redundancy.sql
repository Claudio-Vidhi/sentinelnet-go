CREATE TABLE IF NOT EXISTS redundancy_groups (
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
);

CREATE TABLE IF NOT EXISTS redundancy_members (
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
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_members_group_norm_serial
  ON redundancy_members(redundancy_group_id, norm_serial)
  WHERE norm_serial IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_members_group_index
  ON redundancy_members(redundancy_group_id, member_index)
  WHERE member_index IS NOT NULL;
