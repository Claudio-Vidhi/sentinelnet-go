// Package audit: motore di compliance NetSec Audit e gestione checklist manutenzione.
// Porta di services/netsec_audit/ e services/audit_checklist.py.
package audit

import "math"

const (
	StatusPass    = "PASS"
	StatusFail    = "FAIL"
	StatusWarn    = "WARN"
	StatusUnknown = "UNKNOWN"

	VendorFortiOS = "fortios"
	VendorIOS     = "ios"
	VendorLinux   = "linux"
	VendorGeneric = "generic"
)

type Evidence struct {
	Line    int            `json:"line"`
	Text    string         `json:"text"`
	Context string         `json:"context,omitempty"`
	Message string         `json:"message,omitempty"`
	Params  map[string]any `json:"params,omitempty"`
}

type RuleOutcome struct {
	Status   string         `json:"status"`
	Message  string         `json:"message"`
	Evidence []Evidence     `json:"evidence,omitempty"`
	Params   map[string]any `json:"params,omitempty"`
}

type BenchmarkRule struct {
	ID          string                                  `json:"id"`
	Vendor      string                                  `json:"vendor"`
	Ref         string                                  `json:"ref"`
	Level       int                                     `json:"level"`
	Automated   bool                                    `json:"automated"`
	Title       map[string]string                       `json:"title"`
	Severity    string                                  `json:"severity"`
	Category    string                                  `json:"category"`
	AuditCLI    string                                  `json:"audit"`
	Remediation any                                     `json:"remediation"`
	ChecksDoc   string                                  `json:"checks,omitempty"`
	Check       func(configText string) (RuleOutcome, error) `json:"-"`
}

type RuleResult struct {
	ID          string     `json:"id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	Category    string     `json:"category"`
	Vendor      string     `json:"vendor"`
	Ref         string     `json:"ref"`
	Level       int        `json:"level"`
	Automated   bool       `json:"automated"`
	Status      string     `json:"status"`
	Message     string     `json:"message"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	AuditCLI    string     `json:"audit"`
	Remediation string     `json:"remediation"`
}

type ScoreSummary struct {
	Total   int `json:"total"`
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Warned  int `json:"warned"`
	Unknown int `json:"unknown"`
}

type AuditScanResult struct {
	DeviceName     string        `json:"device_name"`
	Benchmark      string        `json:"benchmark"`
	BenchmarkTitle string        `json:"benchmark_title"`
	Vendor         string        `json:"vendor"`
	Lang           string        `json:"lang"`
	Score          *int          `json:"score"`
	Grade          string        `json:"grade"`
	Summary        ScoreSummary  `json:"summary"`
	Rules          []RuleResult  `json:"rules"`
	SavedID        *int64        `json:"saved_id,omitempty"`
}

func CalculateScore(rules []RuleResult) (*int, ScoreSummary) {
	summary := ScoreSummary{Total: len(rules)}
	for _, r := range rules {
		switch r.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusWarn:
			summary.Warned++
		case StatusUnknown:
			summary.Unknown++
		}
	}
	assessed := summary.Passed + summary.Failed + summary.Warned
	if assessed == 0 {
		return nil, summary
	}
	score := int(math.Round(float64(summary.Passed) / float64(assessed) * 100.0))
	return &score, summary
}

func ScoreGrade(score *int) string {
	if score == nil {
		return "-"
	}
	s := *score
	switch {
	case s >= 90:
		return "A"
	case s >= 75:
		return "B"
	case s >= 60:
		return "C"
	case s >= 40:
		return "D"
	default:
		return "F"
	}
}
