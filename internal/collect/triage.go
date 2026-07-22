package collect

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/driver"
)

// Ping: verifica la raggiungibilità di un host tramite ICMP ping di sistema
// (ping -n 1 -w 1500 su Windows, ping -c 1 -W 2 su Unix) con fallback su probe TCP (porta 22).
func Ping(ctx context.Context, host string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "1500", host)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "2", host)
	}
	if err := cmd.Run(); err == nil {
		return true
	}

	d := net.Dialer{Timeout: 3500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "22"))
	if err == nil {
		_ = conn.Close()
		return true
	}
	return false
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

var hostnameRe = regexp.MustCompile(`(?m)^hostname\s+(\S+)`)

// RunBackupAndTriage: si collega, rileva hostname/versione e scarica la config.
//
// drv fornisce i comandi specifici del vendor: senza di esso venivano inviati
// "show version" e "show running-config" a qualunque apparato, con il risultato
// che HP, Juniper, PAN-OS e AireOS producevano versione non rilevata e backup
// vuoto, silenziosamente. Se nil si usa il driver Cisco IOS (comportamento storico).
func RunBackupAndTriage(ctx context.Context, host string, creds Credentials, drv driver.Driver) TriageResult {
	if drv == nil {
		drv = driver.CiscoIOS{}
	}
	sess, err := Dial(ctx, host, creds)
	if err != nil {
		return TriageResult{Status: "error", Message: err.Error()}
	}
	defer sess.Close()

	version := drv.GetVersion(sess)
	cfg := sess.Run(drv.BackupCommand())

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
	// I driver ritornano "Unknown"; l'inventario Go usa "Non Rilevata".
	if version == "" || version == "Unknown" {
		version = "Non Rilevata"
	}
	res.Version = version
	return res
}
