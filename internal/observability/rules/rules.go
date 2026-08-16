// Package rules: motore deterministico delle regole di correlazione.
// Porta di observability/rules.py.
package rules

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/endpoints"
)

type Role string

const (
	RoleTrigger     Role = "trigger"
	RoleSupporting  Role = "supporting"
	RoleSymptom     Role = "symptom"
	RoleConsequence Role = "consequence"
)

type Finding struct {
	Key        string         `json:"key,omitempty"`
	Interface  string         `json:"interface,omitempty"`
	EventID    int64          `json:"event_id"`
	TS         int64          `json:"ts"`
	Tenant     string         `json:"tenant"`
	Role       Role           `json:"role"`
	EntityKey  string         `json:"entity_key"`
	Summary    string         `json:"summary"`
	Severity   *int           `json:"severity,omitempty"`
	SrcIP      string         `json:"src_ip,omitempty"`
	DstIP      string         `json:"dst_ip,omitempty"`
	SwitchPort string         `json:"switch_port,omitempty"`
	Attrs      map[string]any `json:"attrs,omitempty"`
}

type Retraction struct {
	TargetRuleID string   `json:"target_rule_id"`
	EntityKey    string   `json:"entity_key"`
	Tenant       string   `json:"tenant"`
	Reason       string   `json:"reason"`
	Witness      *Finding `json:"witness"`
	WindowS      int64    `json:"window_s"`
}

type ParameterSpec struct {
	Name        string  `json:"name"`
	Default     float64 `json:"default"`
	Min         float64 `json:"min"`
	Max         float64 `json:"max"`
	Description string  `json:"description"`
}

type RuleDef struct {
	ID             string          `json:"id"`
	Version        string          `json:"version"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Inputs         []string        `json:"inputs"`
	Outputs        []string        `json:"outputs"`
	BaseConfidence int             `json:"base_confidence"`
	Investigation  string          `json:"investigation"`
	Remediation    string          `json:"remediation"`
	Parameters     []ParameterSpec `json:"parameters"`
	Check          func(events []EventRow, p map[string]float64) ([]any, error)
}

type EventRow struct {
	ID          int64          `json:"id"`
	TS          int64          `json:"ts"`
	IngestedTS  int64          `json:"ingested_ts"`
	Tenant      string         `json:"tenant"`
	Source      string         `json:"source"`
	SourceID    *int64         `json:"source_id,omitempty"`
	EventType   string         `json:"event_type"`
	EntityType  string         `json:"entity_type"`
	EntityID    string         `json:"entity_id"`
	Severity    *int           `json:"severity,omitempty"`
	DeviceIP    string         `json:"device_ip,omitempty"`
	Interface   string         `json:"interface,omitempty"`
	SrcIP       string         `json:"src_ip,omitempty"`
	DstIP       string         `json:"dst_ip,omitempty"`
	DstPort     *int           `json:"dst_port,omitempty"`
	Protocol    string         `json:"protocol,omitempty"`
	MetricsJSON string         `json:"metrics_json,omitempty"`
	AttrsJSON   string         `json:"attrs_json,omitempty"`
	DedupKey    string         `json:"dedup_key,omitempty"`
}

var Rules = map[string]RuleDef{}

func register(r RuleDef) {
	Rules[r.ID] = r
}

func init() {
	register(RuleDef{
		ID:             "BLOCKED_TRAFFIC_001",
		Version:        "1.0.0",
		Title:          "Traffico bloccato corroborato da flusso",
		Description:    "Un evento di sicurezza di blocco corroborato da un flusso sulla stessa coppia src/dst.",
		Inputs:         []string{"log.security", "flow.aggregate"},
		Outputs:        []string{"trigger", "supporting"},
		BaseConfidence: 80,
		Parameters: []ParameterSpec{
			{"match_delta_s", 120, 10, 3600, "Delta massimo in secondi fra log e flusso."},
		},
		Check: checkBlockedTraffic,
	})

	register(RuleDef{
		ID:             "HIGH_SEVERITY_LOG_001",
		Version:        "1.0.0",
		Title:          "Log critico o ad alta severit",
		Description:    "Evento di sicurezza o log con severit elevata (<= soglia).",
		Inputs:         []string{"log.security", "log.event"},
		Outputs:        []string{"trigger"},
		BaseConfidence: 65,
		Parameters: []ParameterSpec{
			{"max_severity", 3, 0, 7, "Massima severit syslog (0=Emergency, 3=Error)."},
		},
		Check: checkHighSeverityLog,
	})

	register(RuleDef{
		ID:             "IFACE_FLAPPING_001",
		Version:        "1.0.0",
		Title:          "Interfaccia instabile (flapping)",
		Description:    "Una porta cade e risale ripetutamente nella stessa finestra.",
		Inputs:         []string{"interface.change"},
		Outputs:        []string{"trigger"},
		BaseConfidence: 70,
		Parameters: []ParameterSpec{
			{"min_transitions", 4, 2, 100, "Transizioni minime per rilevare instabilit."},
		},
		Check: checkInterfaceFlapping,
	})

	register(RuleDef{
		ID:             "IFACE_DOWN_001",
		Version:        "1.0.0",
		Title:          "Interfaccia passata a down",
		Description:    "Un'interfaccia passa a stato down.",
		Inputs:         []string{"interface.change"},
		Outputs:        []string{"symptom"},
		BaseConfidence: 60,
		Parameters:     []ParameterSpec{},
		Check:          checkInterfaceDown,
	})

	register(RuleDef{
		ID:             "CONFIG_CHANGE_001",
		Version:        "1.0.0",
		Title:          "Modifica di configurazione o stato",
		Description:    "Variazione di configurazione o stato su apparato o interfaccia.",
		Inputs:         []string{"device.change", "interface.change"},
		Outputs:        []string{"trigger"},
		BaseConfidence: 55,
		Parameters:     []ParameterSpec{},
		Check:          checkConfigChange,
	})

	register(RuleDef{
		ID:             "DEVICE_LOAD_001",
		Version:        "1.0.0",
		Title:          "Carico dell'apparato oltre soglia",
		Description:    "CPU, memoria o disco sopra la soglia.",
		Inputs:         []string{"device.state"},
		Outputs:        []string{"symptom"},
		BaseConfidence: 50,
		Parameters: []ParameterSpec{
			{"max_cpu_pct", 85, 1, 100, "Soglia percentuale CPU."},
			{"max_memory_pct", 90, 1, 100, "Soglia percentuale Memoria."},
			{"max_disk_pct", 90, 1, 100, "Soglia percentuale Disco."},
		},
		Check: checkDeviceLoad,
	})

	register(RuleDef{
		ID:             "TRAFFIC_SPIKE_001",
		Version:        "1.0.0",
		Title:          "Picco di volume nella finestra",
		Description:    "Flusso con volume molto superiore alla mediana della finestra corrente.",
		Inputs:         []string{"flow.aggregate"},
		Outputs:        []string{"supporting"},
		BaseConfidence: 50,
		Parameters: []ParameterSpec{
			{"min_flows", 5, 2, 1000, "Numero minimo di flussi per calcolare la mediana."},
			{"spike_ratio", 10, 2, 1000, "Rapporto moltiplicativo rispetto alla mediana."},
			{"include_control_plane", 0, 0, 1, "Includi traffico broadcast/multicast (0=no, 1=s)."},
		},
		Check: checkTrafficSpike,
	})

	register(RuleDef{
		ID:             "FLOW_EXPORTER_UNKNOWN_001",
		Version:        "1.0.0",
		Title:          "Exporter di flussi fuori inventario",
		Description:    "Un exporter invia flussi da un IP non censito.",
		Inputs:         []string{"platform.exporter_unknown"},
		Outputs:        []string{"trigger"},
		BaseConfidence: 90,
		Parameters: []ParameterSpec{
			{"min_packets", 50, 1, 1000000000, "Pacchetti scartati minimi."},
		},
		Check: checkUnknownExporter,
	})
}

func checkBlockedTraffic(events []EventRow, p map[string]float64) ([]any, error) {
	delta := int64(p["match_delta_s"])
	var flows []EventRow
	for _, e := range events {
		if e.EventType == "flow.aggregate" {
			flows = append(flows, e)
		}
	}
	var out []any
	for _, ev := range events {
		if ev.EventType != "log.security" || ev.SrcIP == "" || ev.DstIP == "" {
			continue
		}
		var match *EventRow
		for i := range flows {
			f := &flows[i]
			if f.Tenant == ev.Tenant && f.SrcIP == ev.SrcIP && f.DstIP == ev.DstIP {
				diff := f.TS - ev.TS
				if diff < 0 {
					diff = -diff
				}
				if diff <= delta+60 {
					match = f
					break
				}
			}
		}
		if match == nil {
			continue
		}
		entity := "ip:" + ev.SrcIP
		var evAttrs map[string]any
		_ = json.Unmarshal([]byte(ev.AttrsJSON), &evAttrs)
		action, _ := evAttrs["action"].(string)

		out = append(out, &Finding{
			EventID:   ev.ID,
			TS:        ev.TS,
			Tenant:    ev.Tenant,
			Role:      RoleTrigger,
			EntityKey: entity,
			Severity:  ev.Severity,
			SrcIP:     ev.SrcIP,
			DstIP:     ev.DstIP,
			Summary:   fmt.Sprintf("Traffico bloccato %s -> %s", endpoints.Describe(ev.SrcIP), endpoints.Describe(ev.DstIP)),
			Attrs:     map[string]any{"action": action},
		})

		var flowMetrics map[string]any
		_ = json.Unmarshal([]byte(match.MetricsJSON), &flowMetrics)
		out = append(out, &Finding{
			EventID:   match.ID,
			TS:        match.TS,
			Tenant:    match.Tenant,
			Role:      RoleSupporting,
			EntityKey: entity,
			SrcIP:     match.SrcIP,
			DstIP:     match.DstIP,
			Summary:   fmt.Sprintf("Flusso corrispondente %s -> %s", endpoints.Describe(match.SrcIP), endpoints.Describe(match.DstIP)),
			Attrs:     map[string]any{"metrics": flowMetrics},
		})
	}
	return out, nil
}

func checkHighSeverityLog(events []EventRow, p map[string]float64) ([]any, error) {
	maxSev := int(p["max_severity"])
	var out []any
	for _, ev := range events {
		if !strings.HasPrefix(ev.EventType, "log.") || ev.Severity == nil || *ev.Severity > maxSev {
			continue
		}
		entity := "ip:" + ev.DeviceIP
		if ev.SrcIP != "" {
			entity = "ip:" + ev.SrcIP
		}
		var attrs map[string]any
		_ = json.Unmarshal([]byte(ev.AttrsJSON), &attrs)
		msg, _ := attrs["message"].(string)
		if msg == "" {
			msg = "Evento critico"
		}
		if len(msg) > 200 {
			msg = msg[:200]
		}
		out = append(out, &Finding{
			EventID:   ev.ID,
			TS:        ev.TS,
			Tenant:    ev.Tenant,
			Role:      RoleTrigger,
			EntityKey: entity,
			Severity:  ev.Severity,
			SrcIP:     ev.SrcIP,
			DstIP:     ev.DstIP,
			Summary:   msg,
			Attrs:     map[string]any{"action": attrs["action"]},
		})
	}
	return out, nil
}

func checkInterfaceFlapping(events []EventRow, p map[string]float64) ([]any, error) {
	minTransitions := int(p["min_transitions"])
	type ifKey struct {
		tenant, deviceIP, iface string
	}
	changes := map[ifKey][]EventRow{}
	for _, ev := range events {
		if ev.EventType != "interface.change" || ev.Interface == "" {
			continue
		}
		var attrs map[string]any
		_ = json.Unmarshal([]byte(ev.AttrsJSON), &attrs)
		field := strings.ToLower(fmt.Sprint(attrs["field"]))
		if strings.Contains(field, "link") || strings.Contains(field, "status") {
			k := ifKey{ev.Tenant, ev.DeviceIP, ev.Interface}
			changes[k] = append(changes[k], ev)
		}
	}
	var out []any
	sev := 3
	for k, seen := range changes {
		if len(seen) < minTransitions {
			continue
		}
		span := seen[len(seen)-1].TS - seen[0].TS
		minutes := span / 60
		if minutes < 1 {
			minutes = 1
		}
		last := seen[len(seen)-1]
		out = append(out, &Finding{
			EventID:   last.ID,
			TS:        last.TS,
			Tenant:    k.tenant,
			Role:      RoleTrigger,
			EntityKey: "ip:" + k.deviceIP,
			Severity:  &sev,
			Key:       "flap:" + k.iface,
			Interface: k.iface,
			Summary:   fmt.Sprintf("Interfaccia %s instabile: %d transizioni in %d minuti", k.iface, len(seen), minutes),
			Attrs: map[string]any{
				"interface":   k.iface,
				"transitions": len(seen),
				"span_s":      span,
			},
		})
	}
	return out, nil
}

func checkInterfaceDown(events []EventRow, _ map[string]float64) ([]any, error) {
	var out []any
	for _, ev := range events {
		if ev.EventType != "interface.change" {
			continue
		}
		var attrs map[string]any
		_ = json.Unmarshal([]byte(ev.AttrsJSON), &attrs)
		after := strings.ToLower(fmt.Sprint(attrs["after"]))
		field := strings.ToLower(fmt.Sprint(attrs["field"]))
		if (after == "down" || after == "0" || after == "false") &&
			(strings.Contains(field, "link") || strings.Contains(field, "status")) {
			out = append(out, &Finding{
				EventID:   ev.ID,
				TS:        ev.TS,
				Tenant:    ev.Tenant,
				Role:      RoleSymptom,
				EntityKey: "ip:" + ev.DeviceIP,
				Severity:  ev.Severity,
				Interface: ev.Interface,
				Summary:   fmt.Sprintf("Interfaccia %s passata a down", ev.Interface),
				Attrs:     attrs,
			})
		}
	}
	return out, nil
}

func checkConfigChange(events []EventRow, _ map[string]float64) ([]any, error) {
	var out []any
	for _, ev := range events {
		if ev.EventType != "device.change" && ev.EventType != "interface.change" {
			continue
		}
		var attrs map[string]any
		_ = json.Unmarshal([]byte(ev.AttrsJSON), &attrs)
		field := fmt.Sprint(attrs["field"])
		if strings.HasSuffix(strings.ToLower(field), ".link") || strings.EqualFold(field, "link") {
			continue
		}
		where := ev.Interface
		if where == "" {
			where = ev.DeviceIP
		}
		out = append(out, &Finding{
			EventID:   ev.ID,
			TS:        ev.TS,
			Tenant:    ev.Tenant,
			Role:      RoleTrigger,
			EntityKey: "ip:" + ev.DeviceIP,
			Severity:  ev.Severity,
			Interface: ev.Interface,
			Summary:   fmt.Sprintf("Modifica su %s: %v %v -> %v", where, attrs["field"], attrs["before"], attrs["after"]),
			Attrs:     attrs,
		})
	}
	return out, nil
}

func checkDeviceLoad(events []EventRow, p map[string]float64) ([]any, error) {
	maxCPU := p["max_cpu_pct"]
	maxMem := p["max_memory_pct"]
	maxDisk := p["max_disk_pct"]
	sev := 4
	var out []any
	for _, ev := range events {
		if ev.EventType != "device.state" {
			continue
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(ev.MetricsJSON), &m)
		checks := []struct {
			field string
			limit float64
			label string
		}{
			{"cpu_pct", maxCPU, "CPU"},
			{"memory_pct", maxMem, "Memoria"},
			{"disk_pct", maxDisk, "Disco"},
		}
		for _, c := range checks {
			v, ok := m[c.field].(float64)
			if !ok || v < c.limit {
				continue
			}
			out = append(out, &Finding{
				EventID:   ev.ID,
				TS:        ev.TS,
				Tenant:    ev.Tenant,
				Role:      RoleSymptom,
				EntityKey: "ip:" + ev.DeviceIP,
				Severity:  &sev,
				Key:       c.field,
				Summary:   fmt.Sprintf("%s al %.0f%% su %s (soglia %.0f%%)", c.label, v, ev.DeviceIP, c.limit),
				Attrs:     map[string]any{"metric": c.field, "value": v, "threshold": c.limit},
			})
		}
	}
	return out, nil
}

func checkTrafficSpike(events []EventRow, p map[string]float64) ([]any, error) {
	minFlows := int(p["min_flows"])
	ratio := p["spike_ratio"]
	incCP := p["include_control_plane"] == 1

	var flows []EventRow
	for _, e := range events {
		if e.EventType == "flow.aggregate" {
			if incCP || endpoints.TrafficDirection(e.SrcIP, e.DstIP) != "control_plane" {
				flows = append(flows, e)
			}
		}
	}
	if len(flows) < minFlows {
		return nil, nil
	}
	var volumes []float64
	for _, f := range flows {
		var m map[string]any
		_ = json.Unmarshal([]byte(f.MetricsJSON), &m)
		bytesVal, _ := m["bytes"].(float64)
		if bytesVal == 0 {
			bytesVal, _ = m["total_bytes"].(float64)
		}
		volumes = append(volumes, bytesVal)
	}
	sort.Float64s(volumes)
	mid := volumes[len(volumes)/2]
	if mid <= 0 {
		return nil, nil
	}

	var out []any
	for _, f := range flows {
		var m map[string]any
		_ = json.Unmarshal([]byte(f.MetricsJSON), &m)
		bytesVal, _ := m["bytes"].(float64)
		if bytesVal == 0 {
			bytesVal, _ = m["total_bytes"].(float64)
		}
		if bytesVal < mid*ratio {
			continue
		}
		out = append(out, &Finding{
			EventID:   f.ID,
			TS:        f.TS,
			Tenant:    f.Tenant,
			Role:      RoleSupporting,
			EntityKey: "ip:" + f.SrcIP,
			SrcIP:     f.SrcIP,
			DstIP:     f.DstIP,
			Summary: fmt.Sprintf("Volume anomalo %s -> %s: %.0f byte contro una mediana di %.0f",
				endpoints.Describe(f.SrcIP), endpoints.Describe(f.DstIP), bytesVal, mid),
			Attrs: map[string]any{
				"bytes":        bytesVal,
				"median_bytes": mid,
				"direction":    endpoints.TrafficDirection(f.SrcIP, f.DstIP),
			},
		})
	}
	return out, nil
}

func checkUnknownExporter(events []EventRow, p map[string]float64) ([]any, error) {
	minPackets := float64(p["min_packets"])
	sev := 2
	var out []any
	for _, ev := range events {
		if ev.EventType != "platform.exporter_unknown" {
			continue
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(ev.MetricsJSON), &m)
		pkts, _ := m["packet_count"].(float64)
		if pkts < minPackets {
			continue
		}
		out = append(out, &Finding{
			EventID:   ev.ID,
			TS:        ev.TS,
			Tenant:    ev.Tenant,
			Role:      RoleTrigger,
			EntityKey: "ip:" + ev.DeviceIP,
			Severity:  &sev,
			Summary:   fmt.Sprintf("Exporter non censito %s: %.0f pacchetti scartati", ev.DeviceIP, pkts),
			Attrs:     m,
		})
	}
	return out, nil
}

// ParamsFor ricava i parametri effettivi per una regola fondendo default e override.
func ParamsFor(ruleID string, overrides map[string]any) map[string]float64 {
	r, ok := Rules[ruleID]
	if !ok {
		return map[string]float64{}
	}
	out := map[string]float64{}
	for _, spec := range r.Parameters {
		out[spec.Name] = spec.Default
	}
	if ruleOverrides, ok := overrides[ruleID].(map[string]any); ok {
		for k, v := range ruleOverrides {
			if num, ok := v.(float64); ok {
				for _, spec := range r.Parameters {
					if spec.Name == k {
						if num < spec.Min {
							num = spec.Min
						}
						if num > spec.Max {
							num = spec.Max
						}
						out[k] = num
						break
					}
				}
			}
		}
	}
	return out
}

// Catalog ritorna la lista di tutte le regole.
func Catalog(overrides map[string]any) []map[string]any {
	var out []map[string]any
	for ruleID, r := range Rules {
		out = append(out, map[string]any{
			"id":              ruleID,
			"version":         r.Version,
			"title":           r.Title,
			"description":     r.Description,
			"inputs":          r.Inputs,
			"outputs":         r.Outputs,
			"base_confidence": r.BaseConfidence,
			"investigation":   r.Investigation,
			"remediation":     r.Remediation,
			"parameters":      r.Parameters,
			"effective":       ParamsFor(ruleID, overrides),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	return out
}

type EvalResult struct {
	RuleID      string             `json:"rule_id"`
	RuleVersion string             `json:"rule_version"`
	Params      map[string]float64 `json:"params"`
	Finding     *Finding           `json:"finding,omitempty"`
	Retraction  *Retraction        `json:"retraction,omitempty"`
}

// Evaluate esegue le regole sugli eventi normalizzati.
func Evaluate(events []EventRow, overrides map[string]any, onlyRules []string) []EvalResult {
	var results []EvalResult
	for ruleID, r := range Rules {
		if len(onlyRules) > 0 {
			matched := false
			for _, only := range onlyRules {
				if only == ruleID {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		p := ParamsFor(ruleID, overrides)
		items, err := r.Check(events, p)
		if err != nil {
			continue
		}
		for _, item := range items {
			res := EvalResult{
				RuleID:      ruleID,
				RuleVersion: r.Version,
				Params:      p,
			}
			if f, ok := item.(*Finding); ok {
				res.Finding = f
				results = append(results, res)
			} else if ret, ok := item.(*Retraction); ok {
				res.Retraction = ret
				results = append(results, res)
			}
		}
	}
	return results
}
