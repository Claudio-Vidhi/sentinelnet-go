package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/configanalyzer"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/fwanalyzer"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/policytest"
	"github.com/go-chi/chi/v5"
)

type flowRequest struct {
	SrcIP       string `json:"src_ip"`
	DstIP       string `json:"dst_ip"`
	Proto       string `json:"proto"`
	SPort       *int   `json:"sport"`
	DPort       *int   `json:"dport"`
	IngressIntf string `json:"ingress_intf"`
	EgressIntf  string `json:"egress_intf"`
	TCPFlags    string `json:"tcp_flags"`
	Established bool   `json:"established"`
	ICMPType    *int   `json:"icmp_type"`
}

type proofRequest struct {
	Witness        flowRequest `json:"witness"`
	ExpectedRuleID string      `json:"expected_rule_id"`
}

func (a *App) loadPolicyEnv(w http.ResponseWriter, r *http.Request, ip string) (any, bool) {
	if !a.deviceIPInScope(w, r, ip) {
		return nil, false
	}
	dev, err := a.store.GetDevice(ip)
	if err != nil || dev == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("Dispositivo %s non trovato.", ip))
		return nil, false
	}

	backupDir := ""
	if a.cfg != nil {
		backupDir = a.cfg.BackupDir()
	}
	content, ok := configanalyzer.LoadBackupRunningConfig(backupDir, ip)
	if !ok || strings.TrimSpace(content) == "" {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("Nessun backup trovato per %s.", ip))
		return nil, false
	}

	cfgType := fwanalyzer.DetectConfigType(content, dev.Vendor)
	switch cfgType {
	case fwanalyzer.TypeFortiOS:
		return policytest.ParseFortiOSConfig(content), true
	case fwanalyzer.TypeIOS:
		return policytest.ParseIOSConfig(content), true
	default:
		writeErr(w, http.StatusUnprocessableEntity,
			fmt.Sprintf("Validazione policy non supportata per configurazioni '%s'. Vendor supportati: fortios, ios.", cfgType))
		return nil, false
	}
}

func aclDeclaration(name, kind string) string {
	if kind == "firewall_policy" {
		return "config firewall policy"
	}
	if kind == "named-ext" {
		return fmt.Sprintf("ip access-list extended %s", name)
	}
	if kind == "named-std" {
		return fmt.Sprintf("ip access-list standard %s", name)
	}
	if strings.HasPrefix(kind, "numbered-") {
		parts := strings.SplitN(kind, "-", 2)
		return fmt.Sprintf("access-list %s (%s)", name, parts[1])
	}
	return name
}

func aclBindings(env any, aclName string) []map[string]string {
	var out []map[string]string
	if iosEnv, ok := env.(*policytest.IOSPolicyEnvironment); ok {
		for ifaceName, info := range iosEnv.Interfaces {
			if aclIn, _ := info["acl_in"].(string); aclIn == aclName {
				out = append(out, map[string]string{"interface": ifaceName, "direction": "in"})
			}
			if aclOut, _ := info["acl_out"].(string); aclOut == aclName {
				out = append(out, map[string]string{"interface": ifaceName, "direction": "out"})
			}
		}
	}
	if out == nil {
		out = []map[string]string{}
	}
	return out
}

// POST /api/policy-test/{ip}/trace
func (a *App) handlePolicyTrace(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	env, ok := a.loadPolicyEnv(w, r, ip)
	if !ok {
		return
	}

	var req flowRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.Proto == "" {
		req.Proto = "tcp"
	}

	flow := policytest.Flow{
		SrcIP:       req.SrcIP,
		DstIP:       req.DstIP,
		Proto:       req.Proto,
		SPort:       req.SPort,
		DPort:       req.DPort,
		IngressIntf: req.IngressIntf,
		EgressIntf:  req.EgressIntf,
		TCPFlags:    req.TCPFlags,
		Established: req.Established,
		ICMPType:    req.ICMPType,
	}

	trace, err := policytest.Evaluate(env, flow)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, trace.ToMap())
}

// GET /api/policy-test/{ip}/examples
func (a *App) handlePolicyExamples(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	env, ok := a.loadPolicyEnv(w, r, ip)
	if !ok {
		return
	}

	var groups []map[string]any

	switch e := env.(type) {
	case *policytest.FortiOSPolicyEnvironment:
		examples := policytest.GenerateRulesetExamples(e.Policies, nil)
		var exMaps []map[string]any
		for _, ex := range examples {
			exMaps = append(exMaps, ex.ToMap())
		}
		groups = append(groups, map[string]any{
			"name":           "firewall policy",
			"kind":           "firewall_policy",
			"declaration":    aclDeclaration("firewall policy", "firewall_policy"),
			"bindings":       []map[string]string{},
			"default_action": "deny",
			"examples":       exMaps,
		})
	case *policytest.IOSPolicyEnvironment:
		for aclName, ruleset := range e.ACLs {
			examples := policytest.GenerateRulesetExamples(ruleset.Rules, nil)
			var exMaps []map[string]any
			for _, ex := range examples {
				exMaps = append(exMaps, ex.ToMap())
			}
			groups = append(groups, map[string]any{
				"name":           aclName,
				"kind":           ruleset.Kind,
				"declaration":    aclDeclaration(aclName, ruleset.Kind),
				"bindings":       aclBindings(env, aclName),
				"default_action": ruleset.DefaultAction,
				"examples":       exMaps,
			})
		}
	}

	if groups == nil {
		groups = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, groups)
}

// GET /api/policy-test/{ip}/findings
func (a *App) handlePolicyFindings(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	env, ok := a.loadPolicyEnv(w, r, ip)
	if !ok {
		return
	}

	findings := policytest.AnalyzePolicyFindings(env)
	var out []map[string]any
	for _, f := range findings {
		out = append(out, f.ToMap())
	}
	if out == nil {
		out = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, out)
}

// POST /api/policy-test/{ip}/prove
func (a *App) handlePolicyProve(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	env, ok := a.loadPolicyEnv(w, r, ip)
	if !ok {
		return
	}

	var req proofRequest
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	flow := policytest.Flow{
		SrcIP:       req.Witness.SrcIP,
		DstIP:       req.Witness.DstIP,
		Proto:       req.Witness.Proto,
		SPort:       req.Witness.SPort,
		DPort:       req.Witness.DPort,
		IngressIntf: req.Witness.IngressIntf,
		EgressIntf:  req.Witness.EgressIntf,
		TCPFlags:    req.Witness.TCPFlags,
		Established: req.Witness.Established,
		ICMPType:    req.Witness.ICMPType,
	}

	trace, err := policytest.Evaluate(env, flow)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	var actual string
	for _, s := range trace.Steps {
		if (s.Kind == "acl_in" || s.Kind == "acl_out" || s.Kind == "policy") && s.RuleID != "" {
			actual = s.RuleID
			break
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"proven":           actual == req.ExpectedRuleID,
		"expected_rule_id": req.ExpectedRuleID,
		"actual_rule_id":   actual,
		"trace":            trace.ToMap(),
	})
}
