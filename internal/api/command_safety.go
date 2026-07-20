package api

import (
	"regexp"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/auth"
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

// bulkDestructiveBlacklist: porta 1:1 di BULK_DESTRUCTIVE_BLACKLIST in
// routers/commands.py. È una lista separata e più corta della blacklist
// generale, e si applica all'invio massivo.
var bulkDestructiveBlacklist = []*regexp.Regexp{
	regexp.MustCompile(`\breload\b`),
	regexp.MustCompile(`\breboot\b`),
	regexp.MustCompile(`\berase\b`),
	regexp.MustCompile(`\bformat\b`),
	regexp.MustCompile(`\bwrite\s+erase\b`),
}

// isBulkCommandAllowed porta is_bulk_command_allowed(): nessun comando
// distruttivo nell'invio massivo, in qualsiasi modalità.
//
// Non ha bypass, nemmeno per gli admin, e non è questione di fiducia: qui il
// comando parte verso decine di apparati insieme, quindi un errore di battitura
// non si ferma al primo. Il Python fa lo stesso.
func isBulkCommandAllowed(command string) bool {
	cmdClean := strings.ToLower(strings.TrimSpace(command))
	for _, re := range bulkDestructiveBlacklist {
		if re.MatchString(cmdClean) {
			return false
		}
	}
	return true
}

// cliBlacklistOperatorsKey: chiave nella tabella settings che dice se la
// blacklist vale anche per gli operatori. Attiva per default, come nel Python.
const cliBlacklistOperatorsKey = "cli_blacklist_operators"

// blacklistAppliesToOperators legge l'impostazione. Qualunque valore diverso
// da "false" lascia la blacklist attiva: una chiave assente, vuota o
// malformata non deve disattivare una protezione.
func (a *App) blacklistAppliesToOperators() bool {
	return a.store.GetSetting(cliBlacklistOperatorsKey, "true") != "false"
}

// commandAllowed porta command_allowed() di routers/commands.py (audit M-1):
// gli admin bypassano sempre la blacklist; gli operatori vi sono soggetti solo
// se l'impostazione cli_blacklist_operators è attiva.
//
// È separata da isCommandSafe perché le domande sono due e distinte: "il
// comando è distruttivo?" e "questo utente può eseguirlo comunque?". Chi
// bypassa finisce comunque in audit — vedi bypassNote.
func (a *App) commandAllowed(command string, claims *auth.Claims) bool {
	if claims != nil && claims.Role == "admin" {
		return true
	}
	if !a.blacklistAppliesToOperators() {
		return true
	}
	return isCommandSafe(command)
}

// bypassNote spiega, nell'audit, perché un comando in blacklist è stato
// comunque consentito.
func bypassNote(claims *auth.Claims) string {
	if claims != nil && claims.Role == "admin" {
		return "(blacklist bypassata: admin)"
	}
	return "(blacklist disattivata per gli operatori)"
}
