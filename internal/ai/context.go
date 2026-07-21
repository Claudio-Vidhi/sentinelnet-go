package ai

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const truncMarker = "\n... [contesto troncato] ...\n"

// clen conta i code point (rune) di s, come len() su una str Python.
func clen(s string) int { return utf8.RuneCountInString(s) }

// ContextCharBudget: budget di contesto in caratteri per il modello. override>0
// vince; altrimenti default prudente per nome modello. Porta di context_char_budget.
func ContextCharBudget(provider, model string, override int) int {
	if override > 0 {
		return override
	}
	name := strings.ToLower(model)
	if name == "" {
		name = strings.ToLower(GetDefaultModel(provider))
	}
	if strings.Contains(name, "gemma") {
		return 24000
	}
	for _, t := range []string{"-lite", "-mini", "haiku", "nano"} {
		if strings.Contains(name, t) {
			return 100000
		}
	}
	if strings.ToLower(strings.TrimSpace(provider)) == "ollama" {
		return 48000
	}
	return 200000
}

// reWord riproduce il \w Unicode di Python (lettere + cifre + underscore) più '.' e '-'.
var reWord = regexp.MustCompile(`[\p{L}\p{N}_.-]{3,}`)

func questionKeywords(q string) map[string]bool {
	out := map[string]bool{}
	for _, w := range reWord.FindAllString(strings.ToLower(q), -1) {
		out[w] = true
	}
	return out
}

func truncateHeadTail(text string, limit int) string {
	r := []rune(text)
	if len(r) <= limit {
		return text
	}
	keep := limit - clen(truncMarker)
	if keep < 0 {
		keep = 0
	}
	head := int(float64(keep) * 0.7) // int(keep*0.7)
	tail := keep - head
	out := string(r[:head]) + truncMarker
	if tail > 0 {
		out += string(r[len(r)-tail:])
	}
	return out
}

// splitSections riproduce re.split(r"\n(?=config |interface |router |vlan |policy|!\n)")
// del Python: il lookahead e' a larghezza zero, quindi lo split avviene su
// OGNI "\n" seguito da uno dei prefissi (o da "!\n"), scartando solo quel
// singolo carattere "\n". Se non ci sono punti di split, si ripiega su
// paragrafi separati da riga vuota.
func splitSections(text string) []string {
	prefixes := []string{"config ", "interface ", "router ", "vlan ", "policy"}
	var splitPoints []int
	for i := 0; i < len(text); i++ {
		if text[i] != '\n' {
			continue
		}
		rest := text[i+1:]
		matched := false
		for _, p := range prefixes {
			if strings.HasPrefix(rest, p) {
				matched = true
				break
			}
		}
		if !matched && len(rest) >= 2 && rest[0] == '!' && rest[1] == '\n' {
			matched = true
		}
		if matched {
			splitPoints = append(splitPoints, i)
		}
	}
	if len(splitPoints) == 0 {
		return regexp.MustCompile(`\n\s*\n`).Split(text, -1)
	}
	parts := make([]string, 0, len(splitPoints)+1)
	start := 0
	for _, i := range splitPoints {
		parts = append(parts, text[start:i])
		start = i + 1 // scarta solo il "\n" nel punto di split
	}
	parts = append(parts, text[start:])
	return parts
}

func filterRelevantSections(text string, keywords map[string]bool, limit int) string {
	if len(keywords) == 0 || clen(text) <= limit {
		return truncateHeadTail(text, limit)
	}
	parts := splitSections(text)
	type scored struct {
		score, idx int
		p          string
	}
	all := make([]scored, len(parts))
	positives := 0
	for i, p := range parts {
		low := strings.ToLower(p)
		s := 0
		for k := range keywords {
			if strings.Contains(low, k) {
				s++
			}
		}
		all[i] = scored{s, i, p}
		if s > 0 {
			positives++
		}
	}
	share := limit
	if positives > 0 {
		share = limit / positives
		if share < 500 {
			share = 500
		}
	}
	order := make([]scored, len(all))
	copy(order, all)
	sort.SliceStable(order, func(a, b int) bool {
		if order[a].score != order[b].score {
			return order[a].score > order[b].score
		}
		return order[a].idx < order[b].idx
	})
	kept := map[int]string{}
	used := 0
	for _, s := range order {
		if s.score <= 0 && len(kept) > 0 {
			break
		}
		capv := share
		if rem := limit - used; rem < capv {
			capv = rem
		}
		if capv < 0 {
			capv = 0
		}
		take := s.p
		if clen(take) > capv {
			take = truncateHeadTail(take, capv)
		}
		if take == "" {
			continue
		}
		kept[s.idx] = take
		used += clen(take) + 1
		if used >= limit {
			break
		}
	}
	if len(kept) == 0 {
		return truncateHeadTail(text, limit)
	}
	idxsSorted := make([]int, 0, len(kept))
	for i := range kept {
		idxsSorted = append(idxsSorted, i)
	}
	sort.Ints(idxsSorted)
	segs := make([]string, 0, len(idxsSorted))
	for _, i := range idxsSorted {
		segs = append(segs, kept[i])
	}
	out := strings.Join(segs, "\n")
	if clen(out) < clen(text) {
		out += truncMarker
	}
	if lim := limit + clen(truncMarker); clen(out) > lim {
		out = string([]rune(out)[:lim])
	}
	return out
}

// FitContext adatta i blocchi al budget in caratteri. Porta di fit_context.
func FitContext(blocks []string, budget int, question string) []string {
	filtered := make([]string, 0, len(blocks))
	for _, b := range blocks {
		if b != "" {
			filtered = append(filtered, b)
		}
	}
	if budget <= 0 {
		return filtered
	}
	total := 0
	for _, b := range filtered {
		total += clen(b)
	}
	if total <= budget {
		return filtered
	}
	kw := questionKeywords(question)
	out := make([]string, 0, len(filtered))
	for _, b := range filtered {
		share := int(float64(budget) * (float64(clen(b)) / float64(total)))
		if share < 400 {
			share = 400
		}
		if clen(b) <= share {
			out = append(out, b)
		} else {
			out = append(out, filterRelevantSections(b, kw, share))
		}
	}
	return out
}
