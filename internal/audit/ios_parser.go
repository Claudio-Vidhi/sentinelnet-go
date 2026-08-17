package audit

import (
	"sort"
	"strings"
)

type IosLine struct {
	Line  int      `json:"line"`
	Text  string   `json:"text"`
	Lower string   `json:"lower"`
	Path  []string `json:"path"`
	Raw   string   `json:"raw"`
	Words []string `json:"words"`
}

func (l IosLine) Parent() string {
	if len(l.Path) > 0 {
		return l.Path[len(l.Path)-1]
	}
	return ""
}

type IosConfig struct {
	Lines  []IosLine
	Blocks map[string][]IosLine
}

func normWS(s string) string {
	fields := strings.Fields(s)
	return strings.ToLower(strings.Join(fields, " "))
}

type indentBlock struct {
	indent int
	header string
}

// ParseIOS parses Cisco IOS / IOS-XE configurations preserving line numbers and block scopes.
func ParseIOS(text string) IosConfig {
	var lines []IosLine
	blocks := make(map[string][]IosLine)
	var stack []indentBlock

	var bannerDelim string
	bannerLines := 0
	inCert := false

	rawLines := strings.Split(text, "\n")
	for lineno := 1; lineno <= len(rawLines); lineno++ {
		body := strings.TrimRight(rawLines[lineno-1], "\r")
		stripped := strings.TrimSpace(body)

		if bannerDelim != "" {
			bannerLines++
			if strings.Contains(body, bannerDelim) || bannerLines >= 100 {
				bannerDelim = ""
			}
			continue
		}

		if inCert {
			if strings.ToLower(stripped) == "quit" {
				inCert = false
			}
			continue
		}

		if stripped == "" || strings.HasPrefix(stripped, "!") {
			continue
		}

		low := normWS(stripped)
		indent := len(body) - len(strings.TrimLeft(body, " \t"))

		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}

		path := make([]string, len(stack))
		for i, b := range stack {
			path[i] = b.header
		}

		entry := IosLine{
			Line:  lineno,
			Text:  stripped,
			Lower: low,
			Path:  path,
			Raw:   body,
			Words: strings.Fields(low),
		}
		lines = append(lines, entry)

		if len(stack) > 0 {
			parentHdr := stack[len(stack)-1].header
			blocks[parentHdr] = append(blocks[parentHdr], entry)
		}

		if strings.HasPrefix(low, "banner ") {
			parts := strings.SplitN(stripped, " ", 3)
			if len(parts) >= 3 && len(parts[2]) > 0 {
				p2 := parts[2]
				delim := p2[:1]
				if strings.HasPrefix(p2, "^") && len(p2) >= 2 {
					delim = p2[:2]
				}
				if strings.Count(p2, delim) < 2 {
					bannerDelim = delim
					bannerLines = 0
				}
			}
			continue
		}

		if strings.HasPrefix(low, "certificate ") {
			inCert = true
			continue
		}

		if _, exists := blocks[low]; !exists {
			blocks[low] = []IosLine{}
		}
		stack = append(stack, indentBlock{indent: indent, header: low})
	}

	return IosConfig{
		Lines:  lines,
		Blocks: blocks,
	}
}

func (c IosConfig) IsEmpty() bool {
	return len(c.Lines) == 0
}

func IosFind(cfg IosConfig, prefixes ...string) []IosLine {
	normPref := make([]string, len(prefixes))
	for i, p := range prefixes {
		normPref[i] = normWS(p)
	}
	var res []IosLine
	for _, l := range cfg.Lines {
		for _, p := range normPref {
			if strings.HasPrefix(l.Lower, p) {
				res = append(res, l)
				break
			}
		}
	}
	return res
}

func IosFindTop(cfg IosConfig, prefixes ...string) []IosLine {
	normPref := make([]string, len(prefixes))
	for i, p := range prefixes {
		normPref[i] = normWS(p)
	}
	var res []IosLine
	for _, l := range cfg.Lines {
		if len(l.Path) == 0 {
			for _, p := range normPref {
				if strings.HasPrefix(l.Lower, p) {
					res = append(res, l)
					break
				}
			}
		}
	}
	return res
}

func IosFirstTop(cfg IosConfig, prefixes ...string) *IosLine {
	hits := IosFindTop(cfg, prefixes...)
	if len(hits) > 0 {
		return &hits[0]
	}
	return nil
}

func IosHasTop(cfg IosConfig, prefixes ...string) bool {
	return len(IosFindTop(cfg, prefixes...)) > 0
}

type IosBlock struct {
	Header string
	Kids   []IosLine
}

func IosBlockHeaderLine(cfg IosConfig, header string) int {
	h := normWS(header)
	for _, l := range cfg.Lines {
		if l.Lower == h {
			return l.Line
		}
	}
	return 0
}

func IosBlocksMatching(cfg IosConfig, prefix string) []IosBlock {
	p := normWS(prefix)
	var out []IosBlock
	for h, kids := range cfg.Blocks {
		if strings.HasPrefix(h, p) {
			out = append(out, IosBlock{Header: h, Kids: kids})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return IosBlockHeaderLine(cfg, out[i].Header) < IosBlockHeaderLine(cfg, out[j].Header)
	})
	return out
}

func IosChild(kids []IosLine, prefixes ...string) *IosLine {
	normPref := make([]string, len(prefixes))
	for i, p := range prefixes {
		normPref[i] = normWS(p)
	}
	for i := range kids {
		k := &kids[i]
		for _, p := range normPref {
			if strings.HasPrefix(k.Lower, p) {
				return k
			}
		}
	}
	return nil
}
