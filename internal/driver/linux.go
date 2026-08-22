package driver

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	reLinuxPretty = regexp.MustCompile(`(?m)^PRETTY_NAME="?([^"\r\n]+)"?`)
	reLinuxKernel = regexp.MustCompile(`(?m)^(\d+\.\d+\.\S+)\s*$`)
)

// LinuxBackupFiles: file di configurazione leggibili da account non privilegiato.
// Replicati da drivers/linux.py (BACKUP_FILES).
var LinuxBackupFiles = []string{
	"/etc/os-release",
	"/etc/ssh/sshd_config",
	"/etc/login.defs",
	"/etc/sysctl.conf",
	"/etc/fstab",
	"/etc/hosts",
	"/etc/resolv.conf",
	"/etc/passwd",
	"/etc/group",
}

// ---- Linux Host (Ubuntu, Debian, RHEL, CentOS, Rocky, Fedora, Alpine, etc.) ----

type LinuxDriver struct{}

func (LinuxDriver) GetVersion(r Runner) string {
	out := r.Run("cat /etc/os-release; uname -r")
	var pretty string
	if m := reLinuxPretty.FindStringSubmatch(out); len(m) == 2 {
		pretty = strings.TrimSpace(m[1])
	}
	if pretty == "" {
		return "Unknown"
	}
	var kernel string
	if m := reLinuxKernel.FindStringSubmatch(out); len(m) == 2 {
		kernel = strings.TrimSpace(m[1])
	}
	if kernel != "" {
		return fmt.Sprintf("%s (%s)", pretty, kernel)
	}
	return pretty
}

func (LinuxDriver) BackupCommand() string {
	var quoted []string
	for _, f := range LinuxBackupFiles {
		quoted = append(quoted, fmt.Sprintf(`"%s"`, f))
	}
	return fmt.Sprintf(`for f in %s; do echo "--- $f ---"; cat "$f" 2>/dev/null; done`, strings.Join(quoted, " "))
}

func (LinuxDriver) ARPCommand() string {
	return "ip neigh show || arp -n"
}
