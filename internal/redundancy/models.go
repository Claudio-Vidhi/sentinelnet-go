package redundancy

import (
	"regexp"
	"strings"
)

type GroupType string

const (
	GroupTypeHAPair GroupType = "ha_pair"
	GroupTypeStack  GroupType = "stack"
	GroupTypeSSO    GroupType = "sso"
)

type MemberRole string

const (
	MemberRoleActive  MemberRole = "active"
	MemberRoleStandby MemberRole = "standby"
	MemberRoleMaster  MemberRole = "master"
	MemberRoleMember  MemberRole = "member"
	MemberRoleUnknown MemberRole = "unknown"
)

type MemberState string

const (
	MemberStateReady           MemberState = "ready"
	MemberStateDown            MemberState = "down"
	MemberStateVersionMismatch MemberState = "version_mismatch"
	MemberStateStandbyHot      MemberState = "standby_hot"
	MemberStateRPDown          MemberState = "rp_down"
	MemberStateProvisioned     MemberState = "provisioned"
	MemberStateUnknown         MemberState = "unknown"
)

type GroupHealth string

const (
	GroupHealthOK         GroupHealth = "ok"
	GroupHealthDegraded   GroupHealth = "degraded"
	GroupHealthOutOfSync  GroupHealth = "out_of_sync"
	GroupHealthSplitBrain GroupHealth = "split_brain"
	GroupHealthUnknown    GroupHealth = "unknown"
)

type MemberInfo struct {
	ID                int64          `json:"id,omitempty"`
	RedundancyGroupID int64          `json:"redundancy_group_id,omitempty"`
	DeviceIP          string         `json:"device_ip,omitempty"`
	MemberIndex       int            `json:"member_index"`
	Role              MemberRole     `json:"role"`
	Serial            string         `json:"serial,omitempty"`
	NormSerial        string         `json:"norm_serial,omitempty"`
	Model             string         `json:"model,omitempty"`
	Firmware          string         `json:"firmware,omitempty"`
	State             MemberState    `json:"state"`
	MgmtIP            string         `json:"mgmt_ip,omitempty"`
	Priority          *int           `json:"priority,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

type GroupInfo struct {
	ID              int64        `json:"id,omitempty"`
	GroupName       string       `json:"group_name"`
	GroupType       GroupType    `json:"group_type"`
	Name            string       `json:"name"`
	VirtualIP       string       `json:"virtual_ip,omitempty"`
	LogicalDeviceIP string       `json:"logical_device_ip,omitempty"`
	Health          GroupHealth  `json:"health"`
	DetectionSource string       `json:"detection_source"`
	LastVerified    string       `json:"last_verified,omitempty"`
	Members         []MemberInfo `json:"members"`
}

var nonAlphanumeric = regexp.MustCompile(`[^A-Za-z0-9]`)

func NormalizeSerial(val string) string {
	if val == "" {
		return ""
	}
	return strings.ToUpper(nonAlphanumeric.ReplaceAllString(val, ""))
}

func (g *GroupInfo) ComputeHealth() GroupHealth {
	activeCount := 0
	for _, m := range g.Members {
		if m.Role == MemberRoleActive || m.Role == MemberRoleMaster {
			activeCount++
		}
	}
	if activeCount > 1 {
		return GroupHealthSplitBrain
	}
	if g.GroupType == GroupTypeHAPair && len(g.Members) < 2 {
		return GroupHealthDegraded
	}
	for _, m := range g.Members {
		if m.State == MemberStateDown || m.State == MemberStateRPDown || m.State == MemberStateVersionMismatch {
			return GroupHealthDegraded
		}
	}
	return GroupHealthOK
}
