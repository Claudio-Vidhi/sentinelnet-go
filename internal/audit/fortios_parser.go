package audit

import (
	"regexp"
	"strings"
)

var fortiTokenRe = regexp.MustCompile(`"[^"]*"|\S+`)

func fortiTokens(s string) []string {
	matches := fortiTokenRe.FindAllString(s, -1)
	res := make([]string, len(matches))
	for i, m := range matches {
		if strings.HasPrefix(m, "\"") && strings.HasSuffix(m, "\"") && len(m) >= 2 {
			res[i] = m[1 : len(m)-1]
		} else {
			res[i] = m
		}
	}
	return res
}

type ConfigRecord struct {
	Path   []string `json:"path"`
	Key    string   `json:"key"`
	Values []string `json:"values"`
	Line   int      `json:"line"`
	Raw    string   `json:"raw"`
}

type ParsedConfig struct {
	Records  []ConfigRecord
	Sections map[string]struct{}
}

func pathKey(parts []string) string {
	return strings.Join(parts, "/")
}

// ParseWithLines parses FortiOS configuration text preserving 1-based line numbers.
func ParseWithLines(text string) ParsedConfig {
	var records []ConfigRecord
	sections := make(map[string]struct{})
	var stack []string

	lines := strings.Split(text, "\n")
	for lineno := 1; lineno <= len(lines); lineno++ {
		raw := strings.TrimRight(lines[lineno-1], "\r")
		s := strings.TrimSpace(raw)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		low := strings.ToLower(s)

		if strings.HasPrefix(low, "config ") {
			name := strings.Trim(strings.TrimSpace(s[7:]), "\"")
			stack = append(stack, name)
			sections[pathKey(stack)] = struct{}{}
		} else if strings.HasPrefix(low, "edit ") {
			name := strings.Trim(strings.TrimSpace(s[5:]), "\"")
			stack = append(stack, name)
			sections[pathKey(stack)] = struct{}{}
		} else if low == "next" || low == "end" {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		} else if strings.HasPrefix(low, "set ") {
			toks := fortiTokens(s)
			if len(toks) >= 2 {
				pathCopy := make([]string, len(stack))
				copy(pathCopy, stack)
				records = append(records, ConfigRecord{
					Path:   pathCopy,
					Key:    strings.ToLower(toks[1]),
					Values: toks[2:],
					Line:   lineno,
					Raw:    raw,
				})
			}
		}
	}

	return ParsedConfig{
		Records:  records,
		Sections: sections,
	}
}

func SectionPresent(cfg ParsedConfig, section string) bool {
	baseKey := pathKey([]string{section})
	_, ok := cfg.Sections[baseKey]
	return ok
}

func SectionEntries(cfg ParsedConfig, section string) map[string][]ConfigRecord {
	baseParts := []string{section}
	baseLen := len(baseParts)
	out := make(map[string][]ConfigRecord)

	for sKey := range cfg.Sections {
		parts := strings.Split(sKey, "/")
		if len(parts) == baseLen+1 && parts[0] == section {
			editName := parts[baseLen]
			if _, exists := out[editName]; !exists {
				out[editName] = []ConfigRecord{}
			}
		}
	}

	for _, r := range cfg.Records {
		if len(r.Path) >= baseLen+1 && r.Path[0] == section {
			editName := r.Path[baseLen]
			out[editName] = append(out[editName], r)
		}
	}

	return out
}

func Setting(cfg ParsedConfig, section string, key string) *ConfigRecord {
	k := strings.ToLower(key)
	for i := range cfg.Records {
		r := &cfg.Records[i]
		if len(r.Path) == 1 && r.Path[0] == section && r.Key == k {
			return r
		}
	}
	return nil
}

func RecordsUnder(cfg ParsedConfig, path ...string) []ConfigRecord {
	var out []ConfigRecord
	pathLen := len(path)
	for _, r := range cfg.Records {
		if len(r.Path) >= pathLen {
			match := true
			for i := 0; i < pathLen; i++ {
				if r.Path[i] != path[i] {
					match = false
					break
				}
			}
			if match {
				out = append(out, r)
			}
		}
	}
	return out
}
