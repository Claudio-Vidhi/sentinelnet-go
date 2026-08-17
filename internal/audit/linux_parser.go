package audit

import (
	"regexp"
	"strings"
)

const SshdEffective = "sshd -T"

var (
	linuxMarkerRe = regexp.MustCompile(`^---\s+(\S.*?)\s+---\s*$`)
	sectionAliases = map[string]string{
		"SSHD EFFECTIVE CONFIG": SshdEffective,
	}
)

type LinuxLine struct {
	Line  int      `json:"line"`
	Text  string   `json:"text"`
	Lower string   `json:"lower"`
	Raw   string   `json:"raw"`
	Words []string `json:"words"`
}

type LinuxConfig struct {
	Lines []LinuxLine
	Files map[string][]LinuxLine
}

func (c LinuxConfig) IsEmpty() bool {
	return len(c.Lines) == 0
}

// ParseLinux splits multi-file Linux backup artifacts by section markers.
func ParseLinux(text string) LinuxConfig {
	var lines []LinuxLine
	files := make(map[string][]LinuxLine)
	var currentName string

	rawLines := strings.Split(text, "\n")
	for lineno := 1; lineno <= len(rawLines); lineno++ {
		body := strings.TrimRight(rawLines[lineno-1], "\r")
		stripped := strings.TrimSpace(body)

		if m := linuxMarkerRe.FindStringSubmatch(stripped); len(m) == 2 {
			name := m[1]
			if alias, ok := sectionAliases[strings.ToUpper(name)]; ok {
				name = alias
			}
			currentName = name
			if _, exists := files[name]; !exists {
				files[name] = []LinuxLine{}
			}
			continue
		}

		if stripped == "" || strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, ";") {
			continue
		}

		low := normWS(stripped)
		entry := LinuxLine{
			Line:  lineno,
			Text:  stripped,
			Lower: low,
			Raw:   body,
			Words: strings.Fields(low),
		}
		lines = append(lines, entry)

		if currentName != "" {
			files[currentName] = append(files[currentName], entry)
		}
	}

	return LinuxConfig{
		Lines: lines,
		Files: files,
	}
}

func LinuxFileLines(cfg LinuxConfig, path string) []LinuxLine {
	return cfg.Files[path]
}

func LinuxHasFile(cfg LinuxConfig, path string) bool {
	_, ok := cfg.Files[path]
	return ok
}

func LinuxDirectives(lines []LinuxLine, keyword string) []LinuxLine {
	k := strings.ToLower(keyword)
	var res []LinuxLine
	for _, l := range lines {
		if len(l.Words) > 0 && l.Words[0] == k {
			res = append(res, l)
		}
	}
	return res
}

func LinuxFirstDirective(lines []LinuxLine, keyword string) *LinuxLine {
	hits := LinuxDirectives(lines, keyword)
	if len(hits) > 0 {
		return &hits[0]
	}
	return nil
}

func LinuxLastDirective(lines []LinuxLine, keyword string) *LinuxLine {
	hits := LinuxDirectives(lines, keyword)
	if len(hits) > 0 {
		return &hits[len(hits)-1]
	}
	return nil
}

func LinuxSysctlValue(lines []LinuxLine, key string) *LinuxLine {
	k := strings.ToLower(key)
	var last *LinuxLine
	for i := range lines {
		l := &lines[i]
		parts := strings.SplitN(l.Lower, "=", 2)
		if strings.TrimSpace(parts[0]) == k {
			last = l
		}
	}
	return last
}

func LinuxFstabEntry(lines []LinuxLine, mountPoint string) *LinuxLine {
	for i := range lines {
		l := &lines[i]
		fields := strings.Fields(l.Text)
		if len(fields) >= 4 && fields[1] == mountPoint {
			return l
		}
	}
	return nil
}

func LinuxFstabOptions(entry LinuxLine) []string {
	fields := strings.Fields(entry.Text)
	if len(fields) >= 4 {
		opts := strings.Split(strings.ToLower(fields[3]), ",")
		for i := range opts {
			opts[i] = strings.TrimSpace(opts[i])
		}
		return opts
	}
	return []string{}
}
