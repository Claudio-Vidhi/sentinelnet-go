package ai

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
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

// TenantContextArgs sono gli argomenti di BuildTenantContext (dati già
// filtrati dal chiamante per UN SOLO tenant/sede).
type TenantContextArgs struct {
	Tenant      string
	Devices     []map[string]any
	GroupInfo   map[string]any
	Site        []map[string]any
	MacStats    map[string]any
	MacRecent   []map[string]any
	ScanSummary string
	// MaxDevices, MaxRecent: 0 => usa il default (100 / 15), come l'unico
	// chiamante Python (build_tenant_context(max_devices=100, max_recent=15)).
	// Per questo un cap letterale di 0 non e' esprimibile (nessun chiamante
	// Go attuale li passa comunque).
	MaxDevices, MaxRecent int
}

// asStr converte un valore JSON generico nella sua rappresentazione stringa,
// riproducendo str(v) di Python: i numeri interi (arrivano come float64 da
// encoding/json) sono resi senza ".0". nil (JSON null) diventa "None" e i
// bool "True"/"False", perche' d.get(k, default) di Python ritorna il valore
// memorizzato (anche None) quando la chiave e' PRESENTE, usando default solo
// se la chiave e' ASSENTE: str(None) == "None".
func asStr(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case bool:
		if x {
			return "True"
		}
		return "False"
	case string:
		return x
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", x)
	}
}

// mapGet riproduce d.get(key, def): ritorna def solo se la chiave e' assente.
func mapGet(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	return asStr(v)
}

// mapGetOr riproduce d.get(key, "") or def: ritorna def se la chiave e'
// assente o il valore e' falsy (stringa vuota).
func mapGetOr(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	v, ok := m[key]
	if !ok {
		return def
	}
	s := asStr(v)
	if s == "" {
		return def
	}
	return s
}

// asStrSlice converte un []any (elementi JSON generici) in []string.
func asStrSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, asStr(e))
	}
	return out
}

// BuildTenantContext costruisce un blocco di contesto compatto (markdown)
// con le informazioni rilevanti per UN SOLO tenant/sede, da usare come
// messaggio di sistema iniettato nella richiesta AI. Porta di
// build_tenant_context: e' un puro formattatore, non applica alcun filtro
// (il chiamante deve aver già filtrato devices/mac_stats/mac_recent).
func BuildTenantContext(a TenantContextArgs) string {
	maxDevices := a.MaxDevices
	if maxDevices == 0 {
		maxDevices = 100
	}
	maxRecent := a.MaxRecent
	if maxRecent == 0 {
		maxRecent = 15
	}

	lines := []string{fmt.Sprintf("## Contesto sede/tenant: %s", a.Tenant)}

	if len(a.GroupInfo) > 0 {
		desc := mapGet(a.GroupInfo, "description", "")
		if desc != "" {
			lines = append(lines, fmt.Sprintf("Descrizione: %s", desc))
		}
	}

	for _, s := range a.Site {
		name := mapGet(s, "name", mapGet(s, "id", "?"))
		mode := mapGet(s, "mode", "?")
		subnets := strings.Join(asStrSlice(s["subnets"]), ", ")
		if subnets == "" {
			subnets = "(nessuna)"
		}
		lastSeen := mapGetOr(s, "last_seen", "mai")
		lines = append(lines, fmt.Sprintf(
			"Config sito VPN '%s': mode=%s, subnets=%s, last_seen=%s",
			name, mode, subnets, lastSeen))
	}

	lines = append(lines, fmt.Sprintf("\nDispositivi (%d totali):", len(a.Devices)))
	devices := a.Devices
	if len(devices) > maxDevices {
		devices = devices[:maxDevices]
	}
	for _, d := range devices {
		lines = append(lines, fmt.Sprintf(
			"- %s | %s | vendor=%s | site=%s",
			mapGet(d, "IP", "?"), mapGetOr(d, "Hostname", "(senza hostname)"),
			mapGet(d, "Vendor", "?"), mapGet(d, "Site", "central")))
	}
	if len(a.Devices) > maxDevices {
		lines = append(lines, fmt.Sprintf("... e altri %d dispositivi (troncato).", len(a.Devices)-maxDevices))
	}

	if len(a.MacStats) > 0 {
		lines = append(lines, fmt.Sprintf(
			"\nMAC history: %s avvistamenti, %s MAC unici, %s switch coinvolti, retention=%sgg",
			mapGet(a.MacStats, "sightings", "0"), mapGet(a.MacStats, "unique_macs", "0"),
			mapGet(a.MacStats, "switches", "0"), mapGet(a.MacStats, "retention_days", "?")))
	}

	if len(a.MacRecent) > 0 {
		lines = append(lines, fmt.Sprintf("\nUltimi avvistamenti MAC (max %d):", maxRecent))
		recent := a.MacRecent
		if len(recent) > maxRecent {
			recent = recent[:maxRecent]
		}
		for _, s := range recent {
			lines = append(lines, fmt.Sprintf(
				"- %s su switch %s if=%s vlan=%s last_seen=%s",
				mapGet(s, "mac", "?"), mapGet(s, "switch_ip", "?"),
				mapGet(s, "interface", "?"), mapGet(s, "vlan", "?"), mapGet(s, "last_seen", "?")))
		}
	}

	if a.ScanSummary != "" {
		lines = append(lines, fmt.Sprintf("\nUltima scansione di rete: %s", a.ScanSummary))
	}

	return strings.Join(lines, "\n")
}
