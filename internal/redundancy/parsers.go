package redundancy

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reFGCPMember = regexp.MustCompile(`(?m)^([a-zA-Z0-9_-]+)\s*:\s*(primary|secondary|master|backup),\s*priority=(\d+),\s*serial=([A-Za-z0-9]+)`)
)

// ParseFortiGateHA analizza l'output di `get system ha status` di FortiOS.
func ParseFortiGateHA(output, groupName, devIP string) *GroupInfo {
	if !strings.Contains(output, "HA Health Status") && !strings.Contains(output, "Cluster Model") && !strings.Contains(output, "Master:") && !strings.Contains(output, "Primary:") {
		if !strings.Contains(strings.ToLower(output), "ha mode") {
			return nil
		}
	}

	g := &GroupInfo{
		GroupName:       groupName,
		GroupType:       GroupTypeHAPair,
		Name:            "FortiGate Cluster",
		LogicalDeviceIP: devIP,
		DetectionSource: "cli_parser",
		Health:          GroupHealthOK,
	}

	matches := reFGCPMember.FindAllStringSubmatch(output, -1)
	for idx, m := range matches {
		role := MemberRoleStandby
		if strings.ToLower(m[2]) == "primary" || strings.ToLower(m[2]) == "master" {
			role = MemberRoleActive
		}
		prio, _ := strconv.Atoi(m[3])
		serial := m[4]

		g.Members = append(g.Members, MemberInfo{
			MemberIndex: idx,
			Role:        role,
			Serial:      serial,
			NormSerial:  NormalizeSerial(serial),
			State:       MemberStateReady,
			Priority:    &prio,
			DeviceIP:    devIP,
		})
	}

	if len(g.Members) == 0 {
		return nil
	}

	g.Health = g.ComputeHealth()
	return g
}

// ParseCiscoSwitchStack analizza l'output di `show switch` di Cisco IOS/IOS-XE.
func ParseCiscoSwitchStack(output, groupName, devIP string) *GroupInfo {
	if !strings.Contains(output, "Switch/Stack Mac Address") && !strings.Contains(output, "Switch#") && !strings.Contains(output, "Role") {
		return nil
	}

	g := &GroupInfo{
		GroupName:       groupName,
		GroupType:       GroupTypeStack,
		Name:            "Cisco Switch Stack",
		LogicalDeviceIP: devIP,
		DetectionSource: "cli_parser",
		Health:          GroupHealthOK,
	}

	lines := strings.Split(output, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		trimmed = strings.TrimPrefix(trimmed, "*")
		trimmed = strings.TrimSpace(trimmed)
		parts := strings.Fields(trimmed)
		if len(parts) >= 5 {
			swNum, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			roleStr := strings.ToLower(parts[1])
			role := MemberRoleMember
			if roleStr == "master" || roleStr == "active" {
				role = MemberRoleMaster
			} else if roleStr == "standby" {
				role = MemberRoleStandby
			}
			stateStr := strings.ToLower(parts[len(parts)-1])
			state := MemberStateReady
			if stateStr != "ready" && stateStr != "ok" {
				state = MemberStateDown
			}

			g.Members = append(g.Members, MemberInfo{
				MemberIndex: swNum,
				Role:        role,
				Model:       parts[2],
				State:       state,
				DeviceIP:    devIP,
			})
		}
	}

	if len(g.Members) == 0 {
		return nil
	}

	g.Health = g.ComputeHealth()
	return g
}
