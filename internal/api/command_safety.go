package api

import (
	"regexp"
	"strings"
)

// commandBlacklist: porta 1:1 di COMMAND_BLACKLIST in app_server.py (Python).
// Pattern con confini di parola, valutati con ricerca (non solo prefisso).
var commandBlacklist = []*regexp.Regexp{
	regexp.MustCompile(`\breload\b`),
	regexp.MustCompile(`\berase\b`),
	regexp.MustCompile(`\bdelete\b`),
	regexp.MustCompile(`\bformat\b`),
	regexp.MustCompile(`\breboot\b`),
	regexp.MustCompile(`\bconf\s+t\b`),
	regexp.MustCompile(`\bconfigure\s+terminal\b`),
	regexp.MustCompile(`\bcopy\s+.*?startup-config\b`),
}

// isCommandSafe porta is_command_safe() da app_server.py: nega i comandi che
// matchano una qualsiasi regex della blacklist (case-insensitive, spazi esterni ignorati).
func isCommandSafe(command string) bool {
	cmdClean := strings.ToLower(strings.TrimSpace(command))
	for _, re := range commandBlacklist {
		if re.MatchString(cmdClean) {
			return false
		}
	}
	return true
}
