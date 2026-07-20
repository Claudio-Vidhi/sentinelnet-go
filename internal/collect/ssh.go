// Package collect: sessioni SSH/CLI verso gli apparati (equivalente Netmiko-lite),
// version detection, backup config, invio comandi e ping check.
package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Credentials struct {
	Username     string
	Password     string
	EnableSecret string
	// Port è la porta SSH; 0 vale 22. Serve al provisioning day-0, dove
	// l'apparato può esporre SSH su una porta non standard e non proviene
	// dall'inventario.
	Port int
}

// Session è una shell interattiva su un apparato, sul modello di Netmiko:
// invia un comando e legge finché non ricompare il prompt.
type Session struct {
	client  *ssh.Client
	session *ssh.Session
	stdin   io.WriteCloser
	stdout  io.Reader
	prompt  string
}

var promptRe = regexp.MustCompile(`(?m)[\r\n]([\w.\-/:@()]+)[#>]\s*$`)

// Dial apre una sessione shell e porta il device in enable + terminal length 0.
func Dial(ctx context.Context, host string, creds Credentials) (*Session, error) {
	cfg := &ssh.ClientConfig{
		User: creds.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(creds.Password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				ans := make([]string, len(questions))
				for i := range ans {
					ans[i] = creds.Password
				}
				return ans, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // lab/apparati gestiti
		Timeout:         12 * time.Second,
		Config: ssh.Config{
			// Apparati legacy (Catalyst/CBS) richiedono cifrari e KEX datati.
			KeyExchanges: []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"},
			Ciphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc", "aes128-gcm@openssh.com"},
		},
	}

	port := creds.Port
	if port == 0 {
		port = 22
	}
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)

	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	if err := sess.RequestPty("vt100", 200, 80, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}

	s := &Session{client: client, session: sess, stdin: stdin, stdout: stdout}
	// Consuma il banner iniziale e cattura il prompt.
	initial := s.drain(2 * time.Second)
	s.prompt = detectPrompt(initial)

	// Entra in enable se abbiamo un secret e il prompt è in modo user (>).
	if creds.EnableSecret != "" && strings.HasSuffix(strings.TrimSpace(s.prompt), ">") {
		s.writeLine("enable")
		out := s.drain(1500 * time.Millisecond)
		if strings.Contains(strings.ToLower(out), "password") {
			s.writeLine(creds.EnableSecret)
			s.drain(1500 * time.Millisecond)
		}
	}
	// Disabilita la paginazione (Cisco/HPE).
	s.writeLine("terminal length 0")
	s.drain(800 * time.Millisecond)
	// Ricalcola il prompt dopo enable.
	s.writeLine("")
	if p := detectPrompt(s.drain(800 * time.Millisecond)); p != "" {
		s.prompt = p
	}
	return s, nil
}

func detectPrompt(s string) string {
	m := promptRe.FindStringSubmatch(s)
	if len(m) == 2 {
		return m[1]
	}
	// fallback: ultima riga non vuota
	lines := strings.Split(strings.TrimRight(s, "\r\n "), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[len(lines)-1])
	}
	return ""
}

func (s *Session) writeLine(cmd string) {
	fmt.Fprintf(s.stdin, "%s\n", cmd)
}

// drain legge tutto ciò che arriva entro idle di inattività.
func (s *Session) drain(idle time.Duration) string {
	var buf bytes.Buffer
	chunk := make([]byte, 8192)
	deadline := time.Now().Add(idle)
	for {
		if rd, ok := s.stdout.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = rd.SetReadDeadline(time.Now().Add(idle))
		}
		done := make(chan struct{})
		var n int
		var err error
		go func() {
			n, err = s.stdout.Read(chunk)
			close(done)
		}()
		select {
		case <-done:
			if n > 0 {
				buf.Write(chunk[:n])
				deadline = time.Now().Add(idle)
			}
			if err != nil {
				return buf.String()
			}
		case <-time.After(idle):
			return buf.String()
		}
		if time.Now().After(deadline) {
			return buf.String()
		}
	}
}

// Run invia un comando e ritorna l'output ripulito dell'eco e del prompt.
func (s *Session) Run(cmd string) string {
	s.writeLine(cmd)
	raw := s.drain(1500 * time.Millisecond)
	return cleanOutput(raw, cmd, s.prompt)
}

// RunConfig entra in configurazione, invia le righe, torna in exec.
func (s *Session) RunConfig(lines []string) string {
	var out strings.Builder
	out.WriteString(s.Run("configure terminal"))
	for _, l := range lines {
		out.WriteString(s.Run(l))
	}
	out.WriteString(s.Run("end"))
	return out.String()
}

func (s *Session) WriteMemory() {
	s.writeLine("write memory")
	s.drain(3 * time.Second)
}

func cleanOutput(raw, cmd, prompt string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	var kept []string
	for i, l := range lines {
		trimmed := strings.TrimSpace(l)
		if i == 0 && strings.Contains(trimmed, strings.TrimSpace(cmd)) {
			continue // eco del comando
		}
		if prompt != "" && strings.HasPrefix(trimmed, prompt) && (strings.HasSuffix(trimmed, "#") || strings.HasSuffix(trimmed, ">")) {
			continue // riga del prompt
		}
		kept = append(kept, l)
	}
	return strings.TrimSpace(strings.Join(kept, "\n"))
}

func (s *Session) Close() {
	if s.session != nil {
		s.writeLine("exit")
		_ = s.session.Close()
	}
	if s.client != nil {
		_ = s.client.Close()
	}
}

// InteractiveBridge collega gli I/O della shell a callback (per il terminale WS).
// Ritorna quando il contesto viene annullato o la sessione si chiude.
type InteractiveBridge struct {
	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser
}

func DialInteractive(ctx context.Context, host string, creds Credentials, onData func([]byte)) (*InteractiveBridge, error) {
	cfg := &ssh.ClientConfig{
		User:            creds.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(creds.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         12 * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{"diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha256", "curve25519-sha256"},
			Ciphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"},
		},
	}
	port := creds.Port
	if port == 0 {
		port = 22
	}
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, host, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	client := ssh.NewClient(c, chans, reqs)
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, err
	}
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	stderr, _ := sess.StderrPipe()
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	b := &InteractiveBridge{client: client, sess: sess, stdin: stdin}
	pump := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				onData(cp)
			}
			if err != nil {
				return
			}
		}
	}
	go pump(stdout)
	if stderr != nil {
		go pump(stderr)
	}
	go func() {
		<-ctx.Done()
		b.Close()
	}()
	return b, nil
}

func (b *InteractiveBridge) Write(p []byte) (int, error) {
	if b.stdin == nil {
		return 0, errors.New("sessione chiusa")
	}
	return b.stdin.Write(p)
}

func (b *InteractiveBridge) Wait() error {
	if b.sess == nil {
		return nil
	}
	return b.sess.Wait()
}

func (b *InteractiveBridge) Close() {
	if b.sess != nil {
		_ = b.sess.Close()
	}
	if b.client != nil {
		_ = b.client.Close()
	}
}
