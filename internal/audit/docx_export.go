package audit

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html"
	"strings"
	"time"
)

const docxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
</Types>`

const docxRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

const docxDocRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`

const docxStyles = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        <w:rFonts w:ascii="Arial" w:hAnsi="Arial" w:cs="Arial"/>
        <w:sz w:val="20"/>
        <w:color w:val="1E293B"/>
      </w:rPr>
    </w:rPrDefault>
  </w:docDefaults>
</w:styles>`

func xmlEsc(s string) string {
	return html.EscapeString(s)
}

func pRun(text, font, color string, szHalfPt int, bold bool) string {
	if text == "" {
		return ""
	}
	var rPr strings.Builder
	rPr.WriteString("<w:rPr>")
	if font != "" {
		rPr.WriteString(fmt.Sprintf(`<w:rFonts w:ascii="%s" w:hAnsi="%s" w:cs="%s"/>`, font, font, font))
	}
	if bold {
		rPr.WriteString("<w:b/>")
	}
	if szHalfPt > 0 {
		rPr.WriteString(fmt.Sprintf(`<w:sz w:val="%d"/>`, szHalfPt))
	}
	if color != "" {
		rPr.WriteString(fmt.Sprintf(`<w:color w:val="%s"/>`, strings.TrimPrefix(color, "#")))
	}
	rPr.WriteString("</w:rPr>")

	// handle newlines in text
	lines := strings.Split(text, "\n")
	var tStr strings.Builder
	for i, l := range lines {
		if i > 0 {
			tStr.WriteString("<w:br/>")
		}
		tStr.WriteString(fmt.Sprintf(`<w:t xml:space="preserve">%s</w:t>`, xmlEsc(l)))
	}

	return fmt.Sprintf("<w:r>%s%s</w:r>", rPr.String(), tStr.String())
}

func pBlock(align string, spaceBefore, spaceAfter int, runs ...string) string {
	var pPr strings.Builder
	if align != "" || spaceBefore > 0 || spaceAfter > 0 {
		pPr.WriteString("<w:pPr>")
		if align != "" {
			pPr.WriteString(fmt.Sprintf(`<w:jc w:val="%s"/>`, align))
		}
		if spaceBefore > 0 || spaceAfter > 0 {
			pPr.WriteString(fmt.Sprintf(`<w:spacing w:before="%d" w:after="%d"/>`, spaceBefore*20, spaceAfter*20))
		}
		pPr.WriteString("</w:pPr>")
	}
	return fmt.Sprintf("<w:p>%s%s</w:p>", pPr.String(), strings.Join(runs, ""))
}

func tcBlock(widthDxa int, bgHex string, topMar, botMar, leftMar, rightMar int, content ...string) string {
	var tcPr strings.Builder
	tcPr.WriteString("<w:tcPr>")
	if widthDxa > 0 {
		tcPr.WriteString(fmt.Sprintf(`<w:tcW w:w="%d" w:type="dxa"/>`, widthDxa))
	}
	if bgHex != "" {
		tcPr.WriteString(fmt.Sprintf(`<w:shd w:val="clear" w:color="auto" w:fill="%s"/>`, strings.TrimPrefix(bgHex, "#")))
	}
	if topMar > 0 || botMar > 0 || leftMar > 0 || rightMar > 0 {
		tcPr.WriteString(fmt.Sprintf(`<w:tcMar><w:top w:w="%d" w:type="dxa"/><w:bottom w:w="%d" w:type="dxa"/><w:left w:w="%d" w:type="dxa"/><w:right w:w="%d" w:type="dxa"/></w:tcMar>`, topMar, botMar, leftMar, rightMar))
	}
	tcPr.WriteString("</w:tcPr>")

	body := strings.Join(content, "")
	if body == "" {
		body = "<w:p/>"
	}
	return fmt.Sprintf("<w:tc>%s%s</w:tc>", tcPr.String(), body)
}

func trBlock(cells ...string) string {
	return fmt.Sprintf("<w:tr>%s</w:tr>", strings.Join(cells, ""))
}

func tblBlock(borderHex string, rows ...string) string {
	var borders string
	if borderHex != "" {
		bVal := strings.TrimPrefix(borderHex, "#")
		borders = fmt.Sprintf(`<w:tblBorders>
      <w:top w:val="single" w:sz="4" w:space="0" w:color="%s"/>
      <w:left w:val="single" w:sz="4" w:space="0" w:color="%s"/>
      <w:bottom w:val="single" w:sz="4" w:space="0" w:color="%s"/>
      <w:right w:val="single" w:sz="4" w:space="0" w:color="%s"/>
      <w:insideH w:val="single" w:sz="4" w:space="0" w:color="%s"/>
      <w:insideV w:val="single" w:sz="4" w:space="0" w:color="%s"/>
    </w:tblBorders>`, bVal, bVal, bVal, bVal, bVal, bVal)
	} else {
		borders = `<w:tblBorders>
      <w:top w:val="none"/><w:left w:val="none"/><w:bottom w:val="none"/><w:right w:val="none"/><w:insideH w:val="none"/><w:insideV w:val="none"/>
    </w:tblBorders>`
	}
	return fmt.Sprintf(`<w:tbl>
    <w:tblPr>
      <w:tblW w:w="10200" w:type="dxa"/>
      <w:jc w:val="center"/>
      %s
    </w:tblPr>
    %s
  </w:tbl>`, borders, strings.Join(rows, ""))
}

// GenerateAuditDOCX creates a formatted .docx binary report from scan result data.
func GenerateAuditDOCX(data map[string]any) ([]byte, error) {
	lang := "it"
	if l, ok := data["lang"].(string); ok && l != "" {
		lang = NormalizeLang(l)
	}
	isEn := (lang == "en")

	device := "Device"
	if d, ok := data["device_name"].(string); ok && d != "" {
		device = d
	} else if d, ok := data["device"].(string); ok && d != "" {
		device = d
	}

	benchmark := "CIS Benchmark"
	if b, ok := data["benchmark_title"].(string); ok && b != "" {
		benchmark = b
	} else if b, ok := data["benchmark"].(string); ok && b != "" {
		benchmark = BenchmarkTitle(b)
	}

	generated := time.Now().Format("2006-01-02 15:04:05")
	if g, ok := data["generated"].(string); ok && g != "" {
		generated = g
	}

	vendor := ""
	if v, ok := data["vendor"].(string); ok {
		vendor = v
	}
	platformName := "FortiOS"
	if vendor == VendorIOS {
		platformName = "Cisco IOS XE"
	} else if vendor == VendorLinux {
		platformName = "Linux"
	} else if vendor != "" {
		platformName = strings.ToUpper(vendor)
	}

	var scoreVal *int
	if sc, ok := data["score"].(float64); ok {
		iSc := int(sc)
		scoreVal = &iSc
	} else if sc, ok := data["score"].(int); ok {
		scoreVal = &sc
	} else if sc, ok := data["score"].(*int); ok {
		scoreVal = sc
	}

	summaryMap := make(map[string]int)
	if s, ok := data["summary"].(map[string]any); ok {
		for k, v := range s {
			if num, ok := v.(float64); ok {
				summaryMap[k] = int(num)
			} else if num, ok := v.(int); ok {
				summaryMap[k] = num
			}
		}
	} else if s, ok := data["summary"].(ScoreSummary); ok {
		summaryMap["total"] = s.Total
		summaryMap["passed"] = s.Passed
		summaryMap["failed"] = s.Failed
		summaryMap["warned"] = s.Warned
		summaryMap["unknown"] = s.Unknown
	}

	var body strings.Builder

	// 1. Header
	subTitle := "Report di Conformità di Sicurezza"
	if isEn {
		subTitle = "Security Compliance Report"
	}
	body.WriteString(pBlock("left", 0, 2,
		pRun("SentinelNet  |  ", "Arial", "0F172A", 36, true),
		pRun(subTitle, "Arial", "475569", 32, true),
	))
	body.WriteString(pBlock("left", 0, 10,
		pRun(benchmark, "Arial", "475569", 22, false),
	))

	// 2. Metadata Table (2 rows, 4 cols)
	metaH := []string{"DISPOSITIVO", "PIATTAFORMA", "BENCHMARK", "DATA GENERAZIONE"}
	if isEn {
		metaH = []string{"TARGET DEVICE", "PLATFORM", "BENCHMARK", "GENERATED ON"}
	}
	metaV := []string{device, platformName, benchmark, generated}
	var metaCellsH, metaCellsV []string
	colW := 2550
	for i := 0; i < 4; i++ {
		metaCellsH = append(metaCellsH, tcBlock(colW, "F8FAFC", 80, 40, 120, 120,
			pBlock("left", 0, 0, pRun(metaH[i], "Arial", "64748B", 17, true)),
		))
		metaCellsV = append(metaCellsV, tcBlock(colW, "F8FAFC", 40, 100, 120, 120,
			pBlock("left", 0, 0, pRun(metaV[i], "Arial", "0F172A", 19, true)),
		))
	}
	body.WriteString(tblBlock("CBD5E1", trBlock(metaCellsH...), trBlock(metaCellsV...)))
	body.WriteString(pBlock("left", 0, 8))

	// 3. Warning banner if unknown > 0
	unknownCount := summaryMap["unknown"]
	totalCount := summaryMap["total"]
	if unknownCount > 0 {
		assessed := totalCount - unknownCount
		wText := fmt.Sprintf("%d controlli su %d sono stati valutati; %d non valutabili per assenza sezioni nel file.", assessed, totalCount, unknownCount)
		wTitle := "Valutazione parziale: "
		if isEn {
			wTitle = "Partial assessment: "
			wText = fmt.Sprintf("%d of %d checks assessed; %d not assessable due to missing sections.", assessed, totalCount, unknownCount)
		}
		body.WriteString(pBlock("left", 4, 8,
			pRun(wTitle, "Arial", "D97706", 19, true),
			pRun(wText, "Arial", "1E293B", 19, false),
		))
	}

	// 4. KPI Table (2 rows, 5 cols)
	scoreStr := "—"
	scoreHex := "10B981"
	if scoreVal != nil {
		scoreStr = fmt.Sprintf("%d%%", *scoreVal)
		if *scoreVal < 50 {
			scoreHex = "EF4444"
		} else if *scoreVal < 80 {
			scoreHex = "F59E0B"
		}
	}
	kpiData := []struct {
		val, lbl, hex string
	}{
		{scoreStr, map[bool]string{true: "COMPLIANCE SCORE", false: "PUNTEGGIO"}[isEn], scoreHex},
		{fmt.Sprintf("%d", summaryMap["passed"]), map[bool]string{true: "COMPLIANT (PASS)", false: "CONFORMI (PASS)"}[isEn], "10B981"},
		{fmt.Sprintf("%d", summaryMap["failed"]), map[bool]string{true: "NON-COMPLIANT (FAIL)", false: "NON CONFORMI (FAIL)"}[isEn], "EF4444"},
		{fmt.Sprintf("%d", summaryMap["warned"]), map[bool]string{true: "WARNINGS (WARN)", false: "AVVISI (WARN)"}[isEn], "F59E0B"},
		{fmt.Sprintf("%d", summaryMap["unknown"]), map[bool]string{true: "NOT ASSESSABLE", false: "NON VALUTABILI"}[isEn], "64748B"},
	}
	var kpiCellsV, kpiCellsL []string
	kpiW := 2040
	for _, kd := range kpiData {
		kpiCellsV = append(kpiCellsV, tcBlock(kpiW, "FFFFFF", 100, 20, 80, 80,
			pBlock("center", 0, 0, pRun(kd.val, "Arial", kd.hex, 32, true)),
		))
		kpiCellsL = append(kpiCellsL, tcBlock(kpiW, "FFFFFF", 20, 100, 80, 80,
			pBlock("center", 0, 0, pRun(kd.lbl, "Arial", "64748B", 15, true)),
		))
	}
	body.WriteString(tblBlock("E2E8F0", trBlock(kpiCellsV...), trBlock(kpiCellsL...)))
	body.WriteString(pBlock("left", 0, 10))

	// 5. Findings Table
	findHeaders := []struct {
		title string
		width int
		align string
	}{
		{map[bool]string{true: "ID / REF", false: "ID / REF"}[isEn], 1500, "left"},
		{map[bool]string{true: "CHECK, GUIDANCE & EVIDENCE", false: "CONTROLLO, GUIDA ED EVIDENZE"}[isEn], 4800, "left"},
		{map[bool]string{true: "SEVERITY", false: "SEVERITÀ"}[isEn], 1000, "center"},
		{map[bool]string{true: "RESULT", false: "ESITO"}[isEn], 1000, "center"},
		{map[bool]string{true: "REMEDIATION (CLI)", false: "RIMEDIO (CLI)"}[isEn], 1900, "left"},
	}
	var fHCells []string
	for _, fh := range findHeaders {
		fHCells = append(fHCells, tcBlock(fh.width, "0F172A", 100, 100, 100, 100,
			pBlock(fh.align, 0, 0, pRun(fh.title, "Arial", "FFFFFF", 17, true)),
		))
	}
	findRows := []string{trBlock(fHCells...)}

	// Parse rules from data
	var rawRules []map[string]any
	if rulesArr, ok := data["rules"].([]any); ok {
		for _, item := range rulesArr {
			if m, ok := item.(map[string]any); ok {
				rawRules = append(rawRules, m)
			}
		}
	} else if rulesObj, ok := data["rules"].([]RuleResult); ok {
		for _, r := range rulesObj {
			guidMap := make(map[string]any)
			for k, v := range r.Guidance {
				guidMap[k] = v
			}
			var evArr []any
			for _, e := range r.Evidence {
				evArr = append(evArr, map[string]any{
					"line":    e.Line,
					"text":    e.Text,
					"context": e.Context,
				})
			}
			rawRules = append(rawRules, map[string]any{
				"id":          r.ID,
				"ref":         r.Ref,
				"level":       r.Level,
				"title":       r.Title,
				"detail":      r.Detail,
				"severity":    r.Severity,
				"status":      r.Status,
				"remediation": r.Remediation,
				"audit":       r.AuditCLI,
				"guidance":    guidMap,
				"evidence":    evArr,
			})
		}
	}

	for _, r := range rawRules {
		rID, _ := r["id"].(string)
		rRef, _ := r["ref"].(string)
		rTitle, _ := r["title"].(string)
		rDetail, _ := r["detail"].(string)
		rSev, _ := r["severity"].(string)
		rStatus, _ := r["status"].(string)
		rRem, _ := r["remediation"].(string)
		rAudit, _ := r["audit"].(string)

		// Col 0: ID / Ref
		var c0Runs []string
		c0Runs = append(c0Runs, pRun(rID, "Consolas", "0F172A", 17, true))
		if rRef != "" {
			c0Runs = append(c0Runs, pRun("\n["+rRef+"]", "Consolas", "64748B", 15, false))
		}
		c0 := tcBlock(1500, "", 80, 80, 100, 100, pBlock("left", 0, 0, c0Runs...))

		// Col 1: Check, Guidance & Evidence
		var c1Blocks []string
		c1Blocks = append(c1Blocks, pBlock("left", 0, 2, pRun(rTitle, "Arial", "0F172A", 19, true)))
		if rDetail != "" {
			c1Blocks = append(c1Blocks, pBlock("left", 0, 4, pRun(rDetail, "Arial", "1E293B", 17, false)))
		}
		if gMap, ok := r["guidance"].(map[string]any); ok && len(gMap) > 0 {
			var gRuns []string
			if why, ok := gMap["why"].(string); ok && why != "" {
				lbl := "Perché conta: "
				if isEn {
					lbl = "Why it matters: "
				}
				gRuns = append(gRuns, pRun(lbl, "Arial", "0F172A", 17, true), pRun(why+"\n", "Arial", "334155", 17, false))
			}
			if imp, ok := gMap["impact"].(string); ok && imp != "" {
				lbl := "Impatto del fix: "
				if isEn {
					lbl = "Impact of the fix: "
				}
				gRuns = append(gRuns, pRun(lbl, "Arial", "0F172A", 17, true), pRun(imp+"\n", "Arial", "334155", 17, false))
			}
			if def, ok := gMap["default"].(string); ok && def != "" {
				lbl := "Default di fabbrica: "
				if isEn {
					lbl = "Factory default: "
				}
				gRuns = append(gRuns, pRun(lbl, "Arial", "0F172A", 17, true), pRun(def, "Arial", "334155", 17, false))
			}
			if len(gRuns) > 0 {
				c1Blocks = append(c1Blocks, pBlock("left", 0, 4, gRuns...))
			}
		}
		if rAudit != "" {
			lbl := "Comando di verifica: "
			if isEn {
				lbl = "Verify command: "
			}
			c1Blocks = append(c1Blocks, pBlock("left", 0, 4,
				pRun(lbl, "Arial", "475569", 16, true),
				pRun(rAudit, "Consolas", "0F172A", 16, false),
			))
		}
		if evArr, ok := r["evidence"].([]any); ok && len(evArr) > 0 {
			evHdr := "EVIDENZE NELLA CONFIGURAZIONE:"
			if isEn {
				evHdr = "EVIDENCE IN CONFIGURATION:"
			}
			c1Blocks = append(c1Blocks, pBlock("left", 2, 1, pRun(evHdr, "Arial", "DC2626", 15, true)))
			for _, eItem := range evArr {
				if eMap, ok := eItem.(map[string]any); ok {
					lineNo := 0
					if ln, ok := eMap["line"].(float64); ok {
						lineNo = int(ln)
					} else if ln, ok := eMap["line"].(int); ok {
						lineNo = ln
					}
					lStr := "—"
					if lineNo > 0 {
						lStr = fmt.Sprintf("Riga %d", lineNo)
						if isEn {
							lStr = fmt.Sprintf("Line %d", lineNo)
						}
					}
					eCtx, _ := eMap["context"].(string)
					eTxt, _ := eMap["text"].(string)
					var eRuns []string
					eRuns = append(eRuns, pRun("["+lStr+"] ", "Consolas", "64748B", 15, false))
					if eCtx != "" {
						eRuns = append(eRuns, pRun(eCtx+": ", "Consolas", "1E293B", 16, true))
					}
					eRuns = append(eRuns, pRun(eTxt, "Consolas", "DC2626", 16, true))
					c1Blocks = append(c1Blocks, pBlock("left", 0, 1, eRuns...))
				}
			}
		}
		c1 := tcBlock(4800, "", 80, 80, 100, 100, c1Blocks...)

		// Col 2: Severity
		sColor := "64748B"
		sUp := strings.ToUpper(rSev)
		if sUp == "CRITICAL" || sUp == "HIGH" {
			sColor = "DC2626"
		} else if sUp == "MEDIUM" {
			sColor = "D97706"
		}
		c2 := tcBlock(1000, "", 80, 80, 60, 60, pBlock("center", 0, 0, pRun(sUp, "Arial", sColor, 16, true)))

		// Col 3: Result
		stColor := "64748B"
		stUp := strings.ToUpper(rStatus)
		if stUp == StatusPass {
			stColor = "16A34A"
		} else if stUp == StatusFail {
			stColor = "DC2626"
		} else if stUp == StatusWarn {
			stColor = "D97706"
		}
		c3 := tcBlock(1000, "", 80, 80, 60, 60, pBlock("center", 0, 0, pRun(stUp, "Arial", stColor, 16, true)))

		// Col 4: Remediation
		remDisp := rRem
		if remDisp == "" {
			remDisp = "—"
		}
		c4 := tcBlock(1900, "F0F9FF", 80, 80, 100, 100, pBlock("left", 0, 0, pRun(remDisp, "Consolas", "0284C7", 16, false)))

		findRows = append(findRows, trBlock(c0, c1, c2, c3, c4))
	}
	body.WriteString(tblBlock("CBD5E1", findRows...))

	// 6. Footer
	body.WriteString(pBlock("left", 16, 0,
		pRun("SentinelNet Security Audit Engine  •  Generato automaticamente da configurazione apparato", "Arial", "64748B", 16, false),
	))

	// Document wrapper with margins (0.6 in = 864 dxa)
	docXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    %s
    <w:sectPr>
      <w:pgSz w:w="11906" w:h="16838"/>
      <w:pgMar w:top="864" w:right="864" w:bottom="864" w:left="864"/>
    </w:sectPr>
  </w:body>
</w:document>`, body.String())

	// Build ZIP
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	files := map[string]string{
		"[Content_Types].xml":        docxContentTypes,
		"_rels/.rels":                docxRels,
		"word/_rels/document.xml.rels": docxDocRels,
		"word/styles.xml":            docxStyles,
		"word/document.xml":          docXML,
	}

	for path, content := range files {
		w, err := zw.Create(path)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(content)); err != nil {
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
