// Package redact: redazione segreti nei contesti destinati a LLM esterni.
// Porta di security/redaction.py — i pattern sono replicati uno a uno.
//
// Va chiamato come UNICO punto di passaggio prima che qualunque dato lasci il
// processo verso un provider LLM (assistente in-app) o un server MCP esterno.
//
// Limiti noti (documentati, non gestiti):
//   - segreti in formati proprietari non elencati nei pattern;
//   - segreti spezzati su più righe (eccetto blocchi PEM, gestiti);
//   - valori binari/base64 generici non riconducibili a un pattern noto.
//
// NON maschera: nomi interfaccia, VLAN, hostname, indirizzi IP (gli IP sono
// materia di policy GDPR separata, non di redazione).
package redact

import (
	"regexp"
	"strings"
)

const Mask = "***REDACTED***"

// Ogni pattern ha un gruppo "secret": è l'unica porzione sostituita, il resto
// della riga viene preservato.
var patterns = []*regexp.Regexp{
	// Cisco IOS: enable secret/password (con o senza tipo hash: "enable secret 5 $1$...")
	regexp.MustCompile(`(?im)^(\s*enable\s+(?:secret|password)(?:\s+level\s+\d+)?(?:\s+\d)?\s+)(?P<secret>\S+)`),
	// Cisco IOS: username ... password/secret [tipo]
	regexp.MustCompile(`(?im)^(\s*username\s+\S+.*?\s(?:password|secret)(?:\s+\d)?\s+)(?P<secret>\S+)`),
	// SNMP community
	regexp.MustCompile(`(?im)^(\s*snmp-server\s+community\s+)(?P<secret>\S+)`),
	// RADIUS/TACACS key (anche "key 7 <hash>")
	regexp.MustCompile(`(?im)^(\s*(?:key|pac\s+key|shared-secret)(?:\s+\d)?\s+)(?P<secret>\S+)`),
	regexp.MustCompile(`(?im)((?:radius|tacacs)(?:-server)?\s+.*?\bkey(?:\s+\d)?\s+)(?P<secret>\S+)`),
	// WPA/PSK generici (Cisco WLC/AireOS, IOS wireless)
	regexp.MustCompile(`(?im)^(\s*(?:wpa-psk|psk|pre-shared-key|passphrase)\s+(?:ascii|hex)?\s*(?:\d\s+)?)(?P<secret>\S+)`),
	// FortiOS: set psksecret / passwd / password / private-key / passphrase
	regexp.MustCompile(`(?im)^(\s*set\s+(?:psksecret|passwd|password|private-key|passphrase|auth-pwd|key)\s+)(?P<secret>.+?)\s*$`),
	// generici api key / token / bearer in testo o comandi
	regexp.MustCompile(`(?i)((?:api[-_]?key|token|bearer|secret[-_]?key|client[-_]?secret)["'\s:=]+)(?P<secret>[A-Za-z0-9_\-\.\+/=]{8,})`),
	// blocchi PEM di chiave privata (multiriga)
	regexp.MustCompile(`(?s)(?P<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)`),
	// blob Fernet (base64 urlsafe che inizia con gAAAAA)
	regexp.MustCompile(`(?P<secret>gAAAAA[A-Za-z0-9_\-]{20,}={0,2})`),
}

// Text maschera i segreti in una stringa. Idempotente.
func Text(s string) string {
	for _, re := range patterns {
		s = replaceSecretGroup(re, s)
	}
	return s
}

// replaceSecretGroup sostituisce lo span del gruppo "secret" di ogni match.
//
// Il Python fa m.group(0).replace(secret, MASK), che sostituisce *tutte* le
// occorrenze del testo del segreto dentro il match; qui si sostituisce esattamente
// lo span catturato. L'esito coincide nei casi reali ed è più preciso quando un
// segreto molto corto compare anche nel prefisso del match.
func replaceSecretGroup(re *regexp.Regexp, s string) string {
	gi := re.SubexpIndex("secret")
	if gi < 0 {
		return s
	}
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		start, end := m[2*gi], m[2*gi+1]
		if start < 0 || start < last {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(Mask)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

// Any maschera i segreti in payload annidati (string, map[string]any, []any).
// Le chiavi delle mappe sono preservate: solo i valori vengono mascherati.
// Tipi non gestiti sono ritornati invariati. Idempotente.
func Any(payload any) any {
	switch v := payload.(type) {
	case string:
		return Text(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = Any(val)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, val := range v {
			out[i] = Any(val)
		}
		return out
	case []string:
		out := make([]string, len(v))
		for i, val := range v {
			out[i] = Text(val)
		}
		return out
	default:
		return payload
	}
}
