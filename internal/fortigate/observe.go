package fortigate

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// Result è la busta comune di tutte le funzioni di osservabilità:
// {"source": "api"|"ssh", "api_error"?: str, "data": ...}.
type Result struct {
	Source   string `json:"source"`
	APIError string `json:"api_error,omitempty"`
	Data     any    `json:"data"`
}

// SSHRunner esegue un comando CLI FortiOS. È il ripiego quando la REST non
// risponde; nil significa "nessun ripiego disponibile".
type SSHRunner func(ctx context.Context, command string) (string, error)

// apiOrSSH prova la REST una volta e, se fallisce, ricade sull'SSH.
//
// Non è un retry generico: è esattamente la sequenza del Python, un tentativo
// per trasporto. Se falliscono entrambi l'errore riporta tutti e due i motivi,
// perché diagnosticare "non funziona" senza sapere quale dei due ha ceduto è
// il caso più frequente sul campo.
func (c *Client) apiOrSSH(ctx context.Context, apiPath string, params map[string]string,
	sshCmd string, ssh SSHRunner) (Result, error) {

	data, apiErr := c.Get(ctx, apiPath, params)
	if apiErr == nil {
		return Result{Source: "api", Data: unwrapResults(data)}, nil
	}
	if ssh == nil {
		return Result{}, apiErr
	}
	out, sshErr := ssh(ctx, sshCmd)
	if sshErr != nil {
		return Result{}, errf("API: %v | SSH: %v", apiErr, sshErr)
	}
	return Result{Source: "ssh", APIError: apiErr.Error(), Data: out}, nil
}

// unwrapResults estrae "results" quando presente: è dove FortiOS mette il
// contenuto utile della maggior parte degli endpoint.
func unwrapResults(data map[string]any) any {
	if r, ok := data["results"]; ok {
		return r
	}
	return data
}

// restOnly esegue una chiamata REST senza ripiego SSH (endpoint cmdb con
// proiezione dei campi, che via CLI non avrebbero un equivalente utile).
func (c *Client) restOnly(ctx context.Context, path, format, filter string) (Result, error) {
	data, err := c.GetCMDB(ctx, path, format, filter)
	if err != nil {
		return Result{}, err
	}
	return Result{Source: "api", Data: unwrapResults(data)}, nil
}

// --- Stato di sistema ---

var reFortiVersion = regexp.MustCompile(`v(\d+\.\d+\.\d+)`)

// SystemStatus fonde i campi della busta REST con quelli di "results":
// a differenza degli altri endpoint, per monitor/system/status version e
// serial stanno al livello superiore e non dentro "results".
func (c *Client) SystemStatus(ctx context.Context, ssh SSHRunner) (Result, error) {
	data, apiErr := c.Get(ctx, "monitor/system/status", nil)
	if apiErr == nil {
		merged := map[string]any{}
		if results, ok := data["results"].(map[string]any); ok {
			for k, v := range results {
				merged[k] = v
			}
		}
		if v, ok := data["version"].(string); ok && merged["version"] == nil {
			merged["version"] = strings.TrimPrefix(v, "v")
		}
		if v, ok := data["serial"].(string); ok && merged["serial"] == nil {
			merged["serial"] = v
		}
		return Result{Source: "api", Data: merged}, nil
	}
	if ssh == nil {
		return Result{}, apiErr
	}
	out, sshErr := ssh(ctx, "get system status")
	if sshErr != nil {
		return Result{}, errf("API: %v | SSH: %v", apiErr, sshErr)
	}
	return Result{Source: "ssh", APIError: apiErr.Error(), Data: parseSystemStatusCLI(out)}, nil
}

// parseSystemStatusCLI estrae hostname/version/model/serial dall'output CLI,
// conservando il testo grezzo in "raw".
func parseSystemStatusCLI(out string) map[string]any {
	info := map[string]any{"raw": out}
	for _, line := range strings.Split(out, "\n") {
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key, val = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(val)
		switch key {
		case "hostname":
			info["hostname"] = val
		case "version":
			// Es. "FortiGate-60F v7.2.5,build1517,230410 (GA.F)"
			if m := reFortiVersion.FindStringSubmatch(val); m != nil {
				info["version"] = m[1]
			} else {
				info["version"] = val
			}
			info["model"] = strings.TrimSpace(strings.Split(val, " v")[0])
		case "serial-number":
			info["serial"] = val
		}
	}
	return info
}

// --- Endpoint con ripiego SSH ---

func (c *Client) Interfaces(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/system/interface",
		map[string]string{"include_vlan": "true"}, "get system interface physical", ssh)
}

func (c *Client) ARPTable(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/network/arp", nil, "get system arp", ssh)
}

func (c *Client) DHCPLeases(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/system/dhcp", nil, "execute dhcp lease-list", ssh)
}

func (c *Client) DeviceInventory(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/user/device/query", nil, "diagnose user device list", ssh)
}

func (c *Client) FirewallPolicies(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "cmdb/firewall/policy", nil, "show firewall policy", ssh)
}

func (c *Client) PolicyStats(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/firewall/policy", nil, "diagnose firewall iprope show 100004", ssh)
}

func (c *Client) Routes(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/router/ipv4", nil, "get router info routing-table all", ssh)
}

func (c *Client) WifiClients(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/wifi/client",
		map[string]string{"with_triangulation": "false"}, "diagnose wireless-controller wlac -c sta", ssh)
}

func (c *Client) ManagedAPs(ctx context.Context, ssh SSHRunner) (Result, error) {
	return c.apiOrSSH(ctx, "monitor/wifi/managed_ap", nil, "diagnose wireless-controller wlac -c wtp", ssh)
}

// Sessions filtra la tabella delle sessioni attive.
func (c *Client) Sessions(ctx context.Context, srcIP, dstIP string, dstPort, count int, ssh SSHRunner) (Result, error) {
	params := map[string]string{}
	filters := []string{}
	if srcIP != "" {
		params["srcaddr"] = srcIP
		filters = append(filters, "diagnose sys session filter src "+srcIP)
	}
	if dstIP != "" {
		params["dstaddr"] = dstIP
		filters = append(filters, "diagnose sys session filter dst "+dstIP)
	}
	if dstPort > 0 {
		params["dport"] = fmt.Sprint(dstPort)
		filters = append(filters, fmt.Sprintf("diagnose sys session filter dport %d", dstPort))
	}
	if count > 0 {
		params["count"] = fmt.Sprint(count)
	}
	// "filter clear" per primo: i filtri di sessione sono stato persistente
	// sull'apparato, e senza azzerarli si ereditano quelli di una diagnosi
	// precedente — restituendo in silenzio le sessioni sbagliate.
	sshCmd := strings.Join(append(
		append([]string{"diagnose sys session filter clear"}, filters...),
		"diagnose sys session list"), "\n")
	if len(params) == 0 {
		params = nil
	}
	return c.apiOrSSH(ctx, "monitor/firewall/session", params, sshCmd, ssh)
}

// --- Endpoint solo REST ---

// FirewallAddresses, PolicyObjects e CustomServices usano la proiezione dei
// campi: su installazioni grandi la risposta completa sarebbe di svariati
// megabyte e la UI ne usa una manciata di colonne.
func (c *Client) FirewallAddresses(ctx context.Context) (Result, error) {
	return c.restOnly(ctx, "cmdb/firewall/address", "name|subnet|type|comment", "")
}

func (c *Client) PolicyObjects(ctx context.Context) (Result, error) {
	return c.restOnly(ctx, "cmdb/firewall/policy",
		"policyid|name|srcintf|dstintf|srcaddr|dstaddr|service|action|status|schedule", "")
}

func (c *Client) CustomServices(ctx context.Context) (Result, error) {
	return c.restOnly(ctx, "cmdb/firewall.service/custom",
		"name|protocol|tcp-portrange|udp-portrange|comment", "")
}

// PolicyLookup chiede al FortiGate quale policy applicherebbe a un flusso.
func (c *Client) PolicyLookup(ctx context.Context, srcIP, dest, protocol string, destPort int, srcIntf string) (Result, error) {
	params := map[string]string{
		"ipv6":     "false",
		"sourceip": srcIP,
		"dest":     dest,
		"protocol": protocol,
	}
	if destPort > 0 {
		params["destport"] = fmt.Sprint(destPort)
	}
	if srcIntf != "" {
		params["srcintf"] = srcIntf
	}
	data, err := c.Get(ctx, "monitor/firewall/policy-lookup", params)
	if err != nil {
		return Result{}, err
	}
	return Result{Source: "api", Data: unwrapResults(data)}, nil
}

// TrafficLogs legge i log di traffico, provando prima il disco e poi la
// memoria: sui modelli senza disco il primo tentativo fallisce sempre.
// Se nessuno dei due risponde ricade sulla CLI ("execute log filter" +
// "execute log display"); in quel caso il device restituito è vuoto, perché
// la CLI non dichiara da quale dei due archivi provengono le righe.
func (c *Client) TrafficLogs(ctx context.Context, srcIP, dstIP, action string, count int,
	logDevice string, ssh SSHRunner) (Result, string, error) {
	devices := []string{"disk", "memory"}
	if logDevice == "memory" {
		devices = []string{"memory", "disk"}
	}
	params := map[string]string{}
	if count > 0 {
		params["rows"] = fmt.Sprint(count)
	}
	var filters []string
	if srcIP != "" {
		filters = append(filters, "srcip=="+srcIP)
	}
	if dstIP != "" {
		filters = append(filters, "dstip=="+dstIP)
	}
	if action != "" {
		filters = append(filters, "action=="+action)
	}
	if len(filters) > 0 {
		params["filter"] = strings.Join(filters, "&")
	}

	var lastErr error
	for _, dev := range devices {
		data, err := c.Get(ctx, "log/"+dev+"/traffic/forward", params)
		if err == nil {
			return Result{Source: "api", Data: unwrapResults(data)}, dev, nil
		}
		lastErr = err
	}
	if ssh == nil {
		return Result{}, "", lastErr
	}

	lines := []string{"execute log filter reset", "execute log filter category traffic"}
	if srcIP != "" {
		lines = append(lines, "execute log filter field srcip "+srcIP)
	}
	if dstIP != "" {
		lines = append(lines, "execute log filter field dstip "+dstIP)
	}
	if action != "" {
		lines = append(lines, "execute log filter field action "+action)
	}
	if count <= 0 || count > 1000 {
		count = 1000
	}
	lines = append(lines, fmt.Sprintf("execute log filter view-lines %d", count),
		"execute log display")

	out, sshErr := ssh(ctx, strings.Join(lines, "\n"))
	if sshErr != nil {
		return Result{}, "", errf("API: %v | SSH: %v", lastErr, sshErr)
	}
	return Result{Source: "ssh", APIError: lastErr.Error(), Data: out}, "", nil
}

// FullConfig scarica il backup della configurazione. Contiene segreti, quindi
// il chiamante deve richiedere privilegi elevati e registrare l'accesso.
func (c *Client) FullConfig(ctx context.Context, ssh SSHRunner) (Result, error) {
	data, apiErr := c.Get(ctx, "monitor/system/config/backup",
		map[string]string{"scope": "global"})
	if apiErr == nil {
		if raw, ok := data["raw"].(string); ok {
			return Result{Source: "api", Data: raw}, nil
		}
		return Result{Source: "api", Data: unwrapResults(data)}, nil
	}
	if ssh == nil {
		return Result{}, apiErr
	}
	out, sshErr := ssh(ctx, "show full-configuration")
	if sshErr != nil {
		return Result{}, errf("API: %v | SSH: %v", apiErr, sshErr)
	}
	return Result{Source: "ssh", APIError: apiErr.Error(), Data: out}, nil
}
