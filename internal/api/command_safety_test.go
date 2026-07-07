package api

import "testing"

func TestIsCommandSafe(t *testing.T) {
	cases := []struct {
		cmd  string
		safe bool
	}{
		{"show run", true},
		{"show mac address-table", true},
		{"reload", false},
		{"  RELOAD  ", false},
		{"erase startup-config", false},
		{"format flash:", false},
		{"reboot", false},
		{"conf t", false},
		{"configure terminal", false},
		{"copy running-config startup-config", false},
		{"copy tftp://1.2.3.4/x startup-config", false},
		{"copy running-config tftp://1.2.3.4/x", true}, // non tocca la startup-config
		{"show reloadstats", true},                      // \breload\b non deve matchare parole più lunghe
		{"interface gi0/1", true},
	}
	for _, c := range cases {
		if got := isCommandSafe(c.cmd); got != c.safe {
			t.Errorf("isCommandSafe(%q) = %v, want %v", c.cmd, got, c.safe)
		}
	}
}
