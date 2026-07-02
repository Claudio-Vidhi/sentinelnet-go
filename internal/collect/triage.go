package collect

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"
)

// Ping: apertura TCP sulla 22 come proxy di raggiungibilità (niente ICMP raw,
// che su Windows richiederebbe privilegi). Sufficiente per il "ping check" UI.
func Ping(ctx context.Context, host string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "22"))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

type TriageResult struct {
	Status     string // success | error
	Hostname   string
	Version    string
	Message    string
	Config     string // running-config completa (per backup + parsing topologia)
	VTPStatus  string // "show vtp status"
	CDPOutput  string // "show cdp neighbors detail"
	LLDPOutput string // "show lldp neighbors detail"
}

var (
	hostnameRe = regexp.MustCompile(`(?m)^hostname\s+(\S+)`)
	iosVerRe   = regexp.MustCompile(`(?i)Version\s+([\w.()]+)`)
)

// RunBackupAndTriage: si collega, rileva hostname/versione e scarica la config.
func RunBackupAndTriage(ctx context.Context, host string, creds Credentials) TriageResult {
	sess, err := Dial(ctx, host, creds)
	if err != nil {
		return TriageResult{Status: "error", Message: err.Error()}
	}
	defer sess.Close()

	verOut := sess.Run("show version")
	cfg := sess.Run("show running-config")

	res := TriageResult{
		Status:     "success",
		Config:     cfg,
		VTPStatus:  sess.Run("show vtp status"),
		CDPOutput:  sess.Run("show cdp neighbors detail"),
		LLDPOutput: sess.Run("show lldp neighbors detail"),
	}
	if m := hostnameRe.FindStringSubmatch(cfg); len(m) == 2 {
		res.Hostname = m[1]
	} else if p := strings.TrimRight(sess.prompt, "#>"); p != "" {
		res.Hostname = p
	}
	if m := iosVerRe.FindStringSubmatch(verOut); len(m) == 2 {
		res.Version = m[1]
	} else {
		res.Version = firstNonEmptyLine(verOut)
	}
	if res.Version == "" {
		res.Version = "Non Rilevata"
	}
	return res
}

func firstNonEmptyLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(l); t != "" {
			if len(t) > 80 {
				t = t[:80]
			}
			return t
		}
	}
	return ""
}
