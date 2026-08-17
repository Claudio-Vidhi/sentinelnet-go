package audit

import "strings"

var fortiosMarkers = []string{
	"config system global",
	"config firewall policy",
	"config system interface",
	"#config-version=",
	"config vdom",
	"config system admin",
}

var iosMarkers = []string{
	"line vty",
	"line con 0",
	"interface gigabitethernet",
	"ip http server",
	"aaa new-model",
	"boot system flash",
	"service password-encryption",
	"interface vlan",
}

var linuxMarkers = []string{
	"--- /etc/ssh/sshd_config ---",
	"--- /etc/login.defs ---",
	"--- /etc/fstab ---",
	"--- /etc/os-release ---",
	"--- /etc/sysctl.conf ---",
}

// DetectVendor recognizes vendor from configuration text using structural grammar markers.
func DetectVendor(configText string) string {
	if strings.TrimSpace(configText) == "" {
		return ""
	}
	low := strings.ToLower(configText)

	fgtCount := 0
	for _, m := range fortiosMarkers {
		fgtCount += strings.Count(low, m)
	}

	iosCount := 0
	for _, m := range iosMarkers {
		iosCount += strings.Count(low, m)
	}

	linuxCount := 0
	for _, m := range linuxMarkers {
		linuxCount += strings.Count(low, m)
	}

	best := 0
	bestVendor := ""

	if fgtCount > best {
		best = fgtCount
		bestVendor = VendorFortiOS
	}
	if iosCount > best {
		best = iosCount
		bestVendor = VendorIOS
	}
	if linuxCount > best {
		best = linuxCount
		bestVendor = VendorLinux
	}

	return bestVendor
}
