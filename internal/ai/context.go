package ai

import (
	"regexp"
	"sort"
	"strings"
)

const truncMarker = "\n... [contesto troncato] ...\n"

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

var reWord = regexp.MustCompile(`[\w.-]{3,}`)

func questionKeywords(q string) map[string]bool {
	out := map[string]bool{}
	for _, w := range reWord.FindAllString(strings.ToLower(q), -1) {
		out[w] = true
	}
	return out
}

func truncateHeadTail(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	keep := limit - len(truncMarker)
	if keep < 0 {
		keep = 0
	}
	head := keep * 7 / 10 // int(keep*0.7)
	tail := keep - head
	out := text[:head] + truncMarker
	if tail > 0 {
		out += text[len(text)-tail:]
	}
	return out
}

// splitSections riproduce re.split(r"\n(?=config |interface |router |vlan |policy|!\n)")
// del Python. Se meno di 2 sezioni, si ripiega su paragrafi separati da riga vuota.
func splitSections(text string) []string {
	// Il match Python e' solo il carattere "\n" (il resto e' lookahead a
	// larghezza zero, mai consumato): il separatore va scartato per intero,
	// non lasciato ne' in coda alla sezione precedente ne' in testa alla
	// successiva.
	re := regexp.MustCompile(`\n(?:config |interface |router |vlan |policy|!\n)`)
	locs := re.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return regexp.MustCompile(`\n\s*\n`).Split(text, -1)
	}
	parts := make([]string, 0, len(locs)+1)
	start := 0
	for _, m := range locs {
		parts = append(parts, text[start:m[0]])
		start = m[0] + 1 // salta solo il carattere "\n" appena consumato
	}
	parts = append(parts, text[start:])
	return parts
}

func filterRelevantSections(text string, keywords map[string]bool, limit int) string {
	if len(keywords) == 0 || len(text) <= limit {
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
		if len(take) > capv {
			take = truncateHeadTail(take, capv)
		}
		if take == "" {
			continue
		}
		kept[s.idx] = take
		used += len(take) + 1
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
	if len(out) < len(text) {
		out += truncMarker
	}
	if lim := limit + len(truncMarker); len(out) > lim {
		out = out[:lim]
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
		total += len(b)
	}
	if total <= budget {
		return filtered
	}
	kw := questionKeywords(question)
	out := make([]string, 0, len(filtered))
	for _, b := range filtered {
		share := budget * len(b) / total
		if share < 400 {
			share = 400
		}
		if len(b) <= share {
			out = append(out, b)
		} else {
			out = append(out, filterRelevantSections(b, kw, share))
		}
	}
	return out
}
