// Package export: costruzione minimale di un .vsdx (Visio) usando solo la stdlib.
// Porta di services/visio_export.py.
package export

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html"
	"math"
	"strconv"
	"strings"
)

const (
	scale         = 0.02
	pageWIn       = 11.0
	pageHIn       = 8.5
	minMarginIn   = 0.5
)

type VisioNode struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Model  string   `json:"model"`
	IP     string   `json:"ip"`
	X      float64  `json:"x"`
	Y      float64  `json:"y"`
	W      *float64 `json:"w,omitempty"`
	H      *float64 `json:"h,omitempty"`
	Fill   string   `json:"fill,omitempty"`
	Border string   `json:"border,omitempty"`
}

type VisioEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label,omitempty"`
	Color  string `json:"color,omitempty"`
}

type VisioPoint [2]float64

type VisioLinePrimitive struct {
	Points []VisioPoint `json:"points"`
	Color  string       `json:"color"`
	Alpha  float64      `json:"alpha"`
	Width  float64      `json:"width"`
	Dash   bool         `json:"dash"`
}

type VisioPolyPrimitive struct {
	Points []VisioPoint `json:"points"`
	Fill   string       `json:"fill"`
	Alpha  float64      `json:"alpha"`
}

type VisioRectPrimitive struct {
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	W     float64 `json:"w"`
	H     float64 `json:"h"`
	Fill  string  `json:"fill"`
	Alpha float64 `json:"alpha"`
}

type VisioTextPrimitive struct {
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	Text  string  `json:"text"`
	Color string  `json:"color"`
	Size  float64 `json:"size"`
	Bold  bool    `json:"bold"`
	W     float64 `json:"w"`
}

type VisioPrimitives struct {
	Lines []VisioLinePrimitive `json:"lines"`
	Polys []VisioPolyPrimitive `json:"polys"`
	Rects []VisioRectPrimitive `json:"rects"`
	Texts []VisioTextPrimitive `json:"texts"`
}

type VisioConnector struct {
	From   string       `json:"from"`
	To     string       `json:"to"`
	Points []VisioPoint `json:"points"`
	Color  string       `json:"color"`
	Width  float64      `json:"width"`
	Dash   bool         `json:"dash"`
}

func hexToRGBFraction(hexColor string) string {
	h := strings.TrimPrefix(hexColor, "#")
	if len(h) != 6 {
		h = "6A5FC1"
	}
	r, err1 := strconv.ParseInt(h[0:2], 16, 64)
	g, err2 := strconv.ParseInt(h[2:4], 16, 64)
	b, err3 := strconv.ParseInt(h[4:6], 16, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		r, g, b = 106, 95, 193
	}
	return fmt.Sprintf("#%02X%02X%02X", r, g, b)
}

func ptSize(px float64) float64 {
	return math.Max(px*scale*72.0, 4.0)
}

func collectBounds(nodes []VisioNode, primitives *VisioPrimitives) (float64, float64, float64, float64) {
	var xs, ys []float64
	for _, n := range nodes {
		w := 80.0
		if n.W != nil {
			w = *n.W
		}
		h := 30.0
		if n.H != nil {
			h = *n.H
		}
		xs = append(xs, n.X-w/2.0, n.X+w/2.0)
		ys = append(ys, n.Y-h/2.0, n.Y+h/2.0)
	}
	if primitives != nil {
		for _, ln := range primitives.Lines {
			for _, p := range ln.Points {
				xs = append(xs, p[0])
				ys = append(ys, p[1])
			}
		}
		for _, poly := range primitives.Polys {
			for _, p := range poly.Points {
				xs = append(xs, p[0])
				ys = append(ys, p[1])
			}
		}
		for _, r := range primitives.Rects {
			xs = append(xs, r.X, r.X+r.W)
			ys = append(ys, r.Y, r.Y+r.H)
		}
		for _, t := range primitives.Texts {
			xs = append(xs, t.X)
			ys = append(ys, t.Y)
		}
	}
	if len(xs) == 0 {
		return 0.0, 0.0, 1.0, 1.0
	}
	minX, maxX := xs[0], xs[0]
	minY, maxY := ys[0], ys[0]
	for _, x := range xs {
		if x < minX {
			minX = x
		}
		if x > maxX {
			maxX = x
		}
	}
	for _, y := range ys {
		if y < minY {
			minY = y
		}
		if y > maxY {
			maxY = y
		}
	}
	return minX, minY, maxX, maxY
}

func BuildVSDX(nodes []VisioNode, edges []VisioEdge, primitives *VisioPrimitives, connectors []VisioConnector) ([]byte, error) {
	minX, minY, maxX, maxY := collectBounds(nodes, primitives)
	for _, c := range connectors {
		for _, p := range c.Points {
			if p[0] < minX {
				minX = p[0]
			}
			if p[0] > maxX {
				maxX = p[0]
			}
			if p[1] < minY {
				minY = p[1]
			}
			if p[1] > maxY {
				maxY = p[1]
			}
		}
	}

	pageW := math.Max((maxX-minX)*scale, 1.0) + 2.0*minMarginIn
	pageH := math.Max((maxY-minY)*scale, 1.0) + 2.0*minMarginIn

	tx := func(x float64) float64 { return (x-minX)*scale + minMarginIn }
	ty := func(y float64) float64 { return (maxY-y)*scale + minMarginIn }

	var shapesXML []string
	shapeID := 1
	nextID := func() int {
		sid := shapeID
		shapeID++
		return sid
	}

	charSection := func(sizePt float64, color string, bold bool) string {
		boldVal := 0
		if bold {
			boldVal = 1
		}
		return fmt.Sprintf(`<Section N="Character"><Row IX="0"><Cell N="Size" V="%.4f" U="PT"/><Cell N="Color" V="%s"/><Cell N="Style" V="%d"/></Row></Section>`, sizePt/72.0, hexToRGBFraction(color), boldVal)
	}

	nodeByID := make(map[string]VisioNode)
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}

	type anchor struct {
		lx, ly float64
		color  string
	}

	nodeAnchors := make(map[string][]anchor)
	anchorIndex := make(map[string]int)

	registerAnchor := func(nodeID string, pt VisioPoint, color string) *int {
		n, ok := nodeByID[nodeID]
		if !ok {
			return nil
		}
		key := fmt.Sprintf("%s_%d_%d", nodeID, int(math.Round(pt[0])), int(math.Round(pt[1])))
		if idx, exists := anchorIndex[key]; exists {
			res := idx
			return &res
		}
		wPx := 80.0
		if n.W != nil {
			wPx = *n.W
		}
		hPx := 30.0
		if n.H != nil {
			hPx = *n.H
		}
		lx := (pt[0] - (n.X - wPx/2.0)) * scale
		ly := ((n.Y + hPx/2.0) - pt[1]) * scale

		lst := nodeAnchors[nodeID]
		idx := len(lst)
		anchorIndex[key] = idx
		nodeAnchors[nodeID] = append(lst, anchor{lx: lx, ly: ly, color: color})
		res := idx
		return &res
	}

	type connGlueInfo struct {
		c       VisioConnector
		fromIdx *int
		toIdx   *int
	}

	var connGlue []connGlueInfo
	for _, c := range connectors {
		if len(c.Points) < 2 {
			continue
		}
		color := c.Color
		if color == "" {
			color = "#78909c"
		}
		connGlue = append(connGlue, connGlueInfo{
			c:       c,
			fromIdx: registerAnchor(c.From, c.Points[0], color),
			toIdx:   registerAnchor(c.To, c.Points[len(c.Points)-1], color),
		})
	}

	positions := make(map[string][2]float64)
	nodeShapeID := make(map[string]int)
	sq := 5.0 * scale

	for _, n := range nodes {
		wPx := 80.0
		if n.W != nil {
			wPx = *n.W
		}
		hPx := 30.0
		if n.H != nil {
			hPx = *n.H
		}
		boxW := math.Max(wPx*scale, 0.3)
		boxH := math.Max(hPx*scale, 0.15)
		px, py := tx(n.X), ty(n.Y)
		positions[n.ID] = [2]float64{px, py}
		sid := nextID()
		nodeShapeID[n.ID] = sid

		var parts []string
		if n.Label != "" {
			parts = append(parts, n.Label)
		} else if n.IP != "" {
			parts = append(parts, n.IP)
		} else {
			parts = append(parts, n.ID)
		}
		if n.Model != "" {
			parts = append(parts, n.Model)
		}
		if n.IP != "" && len(parts) < 3 {
			parts = append(parts, n.IP)
		}
		text := strings.Join(parts, "\n")

		fill := hexToRGBFraction(n.Fill)
		if n.Fill == "" {
			fill = hexToRGBFraction("#E8E4FB")
		}
		border := hexToRGBFraction(n.Border)
		if n.Border == "" {
			border = hexToRGBFraction("#6A5FC1")
		}

		anchors := nodeAnchors[n.ID]
		var connRows []string
		for i, a := range anchors {
			connRows = append(connRows, fmt.Sprintf(`<Row IX="%d"><Cell N="X" V="%.4f"/><Cell N="Y" V="%.4f"/></Row>`, i, a.lx, a.ly))
		}
		connSection := ""
		if len(anchors) > 0 {
			connSection = fmt.Sprintf(`<Section N="Connection">%s</Section>`, strings.Join(connRows, ""))
		}

		var children []string
		inset := 3.5 * scale
		for _, a := range anchors {
			csid := nextID()
			cxL, cyL := a.lx, a.ly
			if cxL <= 0.02 {
				cxL += inset
			} else if cxL >= boxW-0.02 {
				cxL -= inset
			}
			if cyL <= 0.02 {
				cyL += inset
			} else if cyL >= boxH-0.02 {
				cyL -= inset
			}
			children = append(children, fmt.Sprintf(`
            <Shape ID="%d" Type="Shape">
              <Cell N="PinX" V="%.4f"/>
              <Cell N="PinY" V="%.4f"/>
              <Cell N="Width" V="%.4f"/>
              <Cell N="Height" V="%.4f"/>
              <Cell N="LocPinX" V="%.4f"/>
              <Cell N="LocPinY" V="%.4f"/>
              <Cell N="FillForegnd" V="%s"/>
              <Cell N="LinePattern" V="0"/>
              <Section N="Geometry" IX="0">
                <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
                <Row T="LineTo" IX="2"><Cell N="X" V="%.4f"/><Cell N="Y" V="0"/></Row>
                <Row T="LineTo" IX="3"><Cell N="X" V="%.4f"/><Cell N="Y" V="%.4f"/></Row>
                <Row T="LineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="%.4f"/></Row>
                <Row T="LineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
              </Section>
            </Shape>`, csid, cxL, cyL, sq, sq, sq/2.0, sq/2.0, hexToRGBFraction(a.color), sq, sq, sq, sq))
		}

		shapeType := "Shape"
		groupCells := ""
		childrenXML := ""
		if len(children) > 0 {
			shapeType = "Group"
			groupCells = `<Cell N="DisplayMode" V="1"/>`
			childrenXML = fmt.Sprintf(`<Shapes>%s</Shapes>`, strings.Join(children, ""))
		}

		shapesXML = append(shapesXML, fmt.Sprintf(`
        <Shape ID="%d" Type="%s">
          <Cell N="PinX" V="%.4f"/>
          <Cell N="PinY" V="%.4f"/>
          <Cell N="Width" V="%.4f"/>
          <Cell N="Height" V="%.4f"/>
          <Cell N="LocPinX" V="%.4f"/>
          <Cell N="LocPinY" V="%.4f"/>
          <Cell N="FillForegnd" V="%s"/>
          <Cell N="LineColor" V="%s"/>
          <Cell N="LineWeight" V="0.01"/>
          %s
          %s
          %s
          <Section N="Geometry" IX="0">
            <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="2"><Cell N="X" V="%.4f"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="3"><Cell N="X" V="%.4f"/><Cell N="Y" V="%.4f"/></Row>
            <Row T="LineTo" IX="4"><Cell N="X" V="0"/><Cell N="Y" V="%.4f"/></Row>
            <Row T="LineTo" IX="5"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
          </Section>
          <Text>%s</Text>
          %s
        </Shape>`, sid, shapeType, px, py, boxW, boxH, boxW/2.0, boxH/2.0, fill, border, groupCells, charSection(ptSize(12), "#1a2430", false), connSection, boxW, boxW, boxH, boxH, html.EscapeString(text), childrenXML))
	}

	pathShape := func(points []VisioPoint, lineColor string, lineWPx float64, dash bool, fill string, fillAlpha float64, closed bool) {
		type pt2d struct{ x, y float64 }
		pts := make([]pt2d, len(points))
		xs := make([]float64, len(points))
		ys := make([]float64, len(points))
		for i, p := range points {
			pts[i] = pt2d{tx(p[0]), ty(p[1])}
			xs[i] = pts[i].x
			ys[i] = pts[i].y
		}
		x0, y0 := xs[0], ys[0]
		maxX, maxY := xs[0], ys[0]
		for _, x := range xs {
			if x < x0 {
				x0 = x
			}
			if x > maxX {
				maxX = x
			}
		}
		for _, y := range ys {
			if y < y0 {
				y0 = y
			}
			if y > maxY {
				maxY = y
			}
		}
		w := math.Max(maxX-x0, 0.01)
		h := math.Max(maxY-y0, 0.01)
		sid := nextID()

		var rows []string
		for i, p := range pts {
			t := "LineTo"
			if i == 0 {
				t = "MoveTo"
			}
			rows = append(rows, fmt.Sprintf(`<Row T="%s" IX="%d"><Cell N="X" V="%.4f"/><Cell N="Y" V="%.4f"/></Row>`, t, i+1, p.x-x0, p.y-y0))
		}

		var cells []string
		cells = append(cells,
			fmt.Sprintf(`<Cell N="PinX" V="%.4f"/>`, x0),
			fmt.Sprintf(`<Cell N="PinY" V="%.4f"/>`, y0),
			fmt.Sprintf(`<Cell N="Width" V="%.4f"/>`, w),
			fmt.Sprintf(`<Cell N="Height" V="%.4f"/>`, h),
			`<Cell N="LocPinX" V="0"/>`,
			`<Cell N="LocPinY" V="0"/>`,
		)

		if lineColor != "" {
			cells = append(cells, fmt.Sprintf(`<Cell N="LineColor" V="%s"/>`, hexToRGBFraction(lineColor)))
			cells = append(cells, fmt.Sprintf(`<Cell N="LineWeight" V="%.4f"/>`, math.Max(lineWPx*scale, 0.008)))
			if dash {
				cells = append(cells, `<Cell N="LinePattern" V="2"/>`)
			}
		} else {
			cells = append(cells, `<Cell N="LinePattern" V="0"/>`)
		}

		geoCells := ""
		if fill != "" {
			cells = append(cells, fmt.Sprintf(`<Cell N="FillForegnd" V="%s"/>`, hexToRGBFraction(fill)))
			if fillAlpha < 1.0 {
				cells = append(cells, fmt.Sprintf(`<Cell N="FillForegndTrans" V="%.3f"/>`, 1.0-fillAlpha))
			}
		} else {
			geoCells = `<Cell N="NoFill" V="1"/>`
		}

		shapesXML = append(shapesXML, fmt.Sprintf(`
        <Shape ID="%d" Type="Shape">
          %s
          <Section N="Geometry" IX="0">
            %s
            %s
          </Section>
        </Shape>`, sid, strings.Join(cells, ""), geoCells, strings.Join(rows, "")))
	}

	textShape := func(cx, cy float64, text string, color string, sizePx float64, bold bool, wPx float64) {
		sid := nextID()
		w := len(text) * int(sizePx)
		if wPx > 0 {
			w = int(wPx)
		}
		widthIn := math.Max(float64(w)*scale, 0.1)
		heightIn := math.Max(sizePx*1.4*scale, 0.08)
		pt := ptSize(sizePx)

		shapesXML = append(shapesXML, fmt.Sprintf(`
        <Shape ID="%d" Type="Shape">
          <Cell N="PinX" V="%.4f"/>
          <Cell N="PinY" V="%.4f"/>
          <Cell N="Width" V="%.4f"/>
          <Cell N="Height" V="%.4f"/>
          <Cell N="LocPinX" V="%.4f"/>
          <Cell N="LocPinY" V="%.4f"/>
          <Cell N="LinePattern" V="0"/>
          <Cell N="FillPattern" V="0"/>
          %s
          <Text>%s</Text>
        </Shape>`, sid, tx(cx), ty(cy), widthIn, heightIn, widthIn/2.0, heightIn/2.0, charSection(pt, color, bold), html.EscapeString(text)))
	}

	var connectsXML []string
	for _, g := range connGlue {
		c := g.c
		type pt2d struct{ x, y float64 }
		pts := make([]pt2d, len(c.Points))
		xs := make([]float64, len(c.Points))
		ys := make([]float64, len(c.Points))
		for i, p := range c.Points {
			pts[i] = pt2d{tx(p[0]), ty(p[1])}
			xs[i] = pts[i].x
			ys[i] = pts[i].y
		}
		x0, y0 := xs[0], ys[0]
		maxX, maxY := xs[0], ys[0]
		for _, x := range xs {
			if x < x0 {
				x0 = x
			}
			if x > maxX {
				maxX = x
			}
		}
		for _, y := range ys {
			if y < y0 {
				y0 = y
			}
			if y > maxY {
				maxY = y
			}
		}
		w := math.Max(maxX-x0, 0.01)
		h := math.Max(maxY-y0, 0.01)
		sid := nextID()

		var rows []string
		for i, p := range pts {
			fx := (p.x - x0) / w
			fy := (p.y - y0) / h
			t := "LineTo"
			if i == 0 {
				t = "MoveTo"
			}
			rows = append(rows, fmt.Sprintf(`<Row T="%s" IX="%d"><Cell N="X" V="%.4f" F="Width*%.6f"/><Cell N="Y" V="%.4f" F="Height*%.6f"/></Row>`, t, i+1, p.x-x0, fx, p.y-y0, fy))
		}
		dashCell := ""
		if c.Dash {
			dashCell = `<Cell N="LinePattern" V="2"/>`
		}
		widthVal := c.Width
		if widthVal <= 0 {
			widthVal = 1.8
		}

		shapesXML = append(shapesXML, fmt.Sprintf(`
        <Shape ID="%d" Type="Shape">
          <Cell N="ObjType" V="2"/>
          <Cell N="ConFixedCode" V="2"/>
          <Cell N="ShapeRouteStyle" V="16"/>
          <Cell N="BeginX" V="%.4f"/>
          <Cell N="BeginY" V="%.4f"/>
          <Cell N="EndX" V="%.4f"/>
          <Cell N="EndY" V="%.4f"/>
          <Cell N="PinX" V="%.4f"/>
          <Cell N="PinY" V="%.4f"/>
          <Cell N="Width" V="%.4f"/>
          <Cell N="Height" V="%.4f"/>
          <Cell N="LocPinX" V="0"/>
          <Cell N="LocPinY" V="0"/>
          <Cell N="LineColor" V="%s"/>
          <Cell N="LineWeight" V="%.4f"/>
          %s
          <Section N="Geometry" IX="0">
            <Cell N="NoFill" V="1"/>
            %s
          </Section>
        </Shape>`, sid, pts[0].x, pts[0].y, pts[len(pts)-1].x, pts[len(pts)-1].y, x0, y0, w, h, hexToRGBFraction(c.Color), math.Max(widthVal*scale, 0.008), dashCell, strings.Join(rows, "")))

		if nid, ok := nodeShapeID[c.From]; ok && g.fromIdx != nil {
			connectsXML = append(connectsXML, fmt.Sprintf(`<Connect FromSheet="%d" FromCell="BeginX" FromPart="9" ToSheet="%d" ToCell="Connections.X%d" ToPart="%d"/>`, sid, nid, *g.fromIdx+1, 100+*g.fromIdx))
		}
		if nid, ok := nodeShapeID[c.To]; ok && g.toIdx != nil {
			connectsXML = append(connectsXML, fmt.Sprintf(`<Connect FromSheet="%d" FromCell="EndX" FromPart="12" ToSheet="%d" ToCell="Connections.X%d" ToPart="%d"/>`, sid, nid, *g.toIdx+1, 100+*g.toIdx))
		}
	}

	if primitives != nil {
		for _, poly := range primitives.Polys {
			if len(poly.Points) > 2 {
				alpha := poly.Alpha
				if alpha <= 0 {
					alpha = 1.0
				}
				pathShape(poly.Points, "", 0, false, poly.Fill, alpha, true)
			}
		}
		for _, r := range primitives.Rects {
			pts := []VisioPoint{
				{r.X, r.Y},
				{r.X + r.W, r.Y},
				{r.X + r.W, r.Y + r.H},
				{r.X, r.Y + r.H},
				{r.X, r.Y},
			}
			alpha := r.Alpha
			if alpha <= 0 {
				alpha = 1.0
			}
			pathShape(pts, "", 0, false, r.Fill, alpha, true)
		}
		for _, ln := range primitives.Lines {
			if len(ln.Points) > 1 {
				c := ln.Color
				if c == "" {
					c = "#78909c"
				}
				w := ln.Width
				if w <= 0 {
					w = 1.5
				}
				pathShape(ln.Points, c, w, ln.Dash, "", 1.0, false)
			}
		}
		for _, t := range primitives.Texts {
			if t.Text != "" {
				c := t.Color
				if c == "" {
					c = "#455a64"
				}
				sz := t.Size
				if sz <= 0 {
					sz = 10.0
				}
				textShape(t.X, t.Y, t.Text, c, sz, t.Bold, t.W)
			}
		}
	} else {
		for _, e := range edges {
			sp, ok1 := positions[e.Source]
			dp, ok2 := positions[e.Target]
			if !ok1 || !ok2 {
				continue
			}
			sid := nextID()
			color := hexToRGBFraction(e.Color)
			w := dp[0] - sp[0]
			h := dp[1] - sp[1]
			shapesXML = append(shapesXML, fmt.Sprintf(`
        <Shape ID="%d" Type="Shape">
          <Cell N="PinX" V="%.4f"/>
          <Cell N="PinY" V="%.4f"/>
          <Cell N="Width" V="%.4f"/>
          <Cell N="Height" V="%.4f"/>
          <Cell N="LocPinX" V="0"/>
          <Cell N="LocPinY" V="0"/>
          <Cell N="LineColor" V="%s"/>
          <Cell N="LineWeight" V="0.02"/>
          <Section N="Geometry" IX="0">
            <Cell N="NoFill" V="1"/>
            <Row T="MoveTo" IX="1"><Cell N="X" V="0"/><Cell N="Y" V="0"/></Row>
            <Row T="LineTo" IX="2"><Cell N="X" V="%.4f"/><Cell N="Y" V="%.4f"/></Row>
          </Section>
          <Text>%s</Text>
        </Shape>`, sid, sp[0], sp[1], math.Max(math.Abs(w), 0.01), math.Max(math.Abs(h), 0.01), color, w, h, html.EscapeString(e.Label)))
		}
	}

	connectsBlock := ""
	if len(connectsXML) > 0 {
		connectsBlock = fmt.Sprintf("\n  <Connects>%s</Connects>", strings.Join(connectsXML, ""))
	}

	pageXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<PageContents xmlns="http://schemas.microsoft.com/office/visio/2012/main" xml:space="preserve">
  <Shapes>%s
  </Shapes>%s
</PageContents>`, strings.Join(shapesXML, ""), connectsBlock)

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/>
  <Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>
  <Override PartName="/visio/pages/page1.xml" ContentType="application/vnd.ms-visio.page+xml"/>
  <Override PartName="/visio/windows.xml" ContentType="application/vnd.ms-visio.windows+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  <Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>
</Types>`

	rootRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/document" Target="visio/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>
</Relationships>`

	documentXML := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<VisioDocument xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xml:space="preserve"/>`

	documentRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/pages" Target="pages/pages.xml"/>
  <Relationship Id="rId2" Type="http://schemas.microsoft.com/visio/2010/relationships/windows" Target="windows.xml"/>
</Relationships>`

	windowsXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Windows xmlns="http://schemas.microsoft.com/office/visio/2012/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" ClientWidth="1600" ClientHeight="900" xml:space="preserve">
  <Window ID="0" WindowType="Drawing" WindowState="1073741824" ContainerType="Page" Page="0" ViewScale="1" ViewCenterX="%.4f" ViewCenterY="%.4f"/>
</Windows>`, pageW/2.0, pageH/2.0)

	coreProps := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>SentinelNet Map</dc:title>
  <dc:creator>SentinelNet</dc:creator>
</cp:coreProperties>`

	appProps := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Microsoft Visio</Application>
</Properties>`

	customProps := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="IsMetric"><vt:bool>false</vt:bool></property>
</Properties>`

	pagesXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Pages xmlns="http://schemas.microsoft.com/office/visio/2012/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <Page ID="0" NameU="Page-1" Name="SentinelNet Map">
    <PageSheet>
      <Cell N="PageWidth" V="%.4f"/>
      <Cell N="PageHeight" V="%.4f"/>
      <Cell N="PageScale" V="1" U="IN_F"/>
      <Cell N="DrawingScale" V="1" U="IN_F"/>
      <Cell N="DrawingSizeType" V="3"/>
      <Cell N="DrawingScaleType" V="0"/>
    </PageSheet>
    <Rel r:id="rId1"/>
  </Page>
</Pages>`, pageW, pageH)

	pagesRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.microsoft.com/visio/2010/relationships/page" Target="page1.xml"/>
</Relationships>`

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	files := map[string]string{
		"[Content_Types].xml":               contentTypes,
		"_rels/.rels":                       rootRels,
		"docProps/core.xml":                 coreProps,
		"docProps/app.xml":                  appProps,
		"docProps/custom.xml":               customProps,
		"visio/document.xml":                documentXML,
		"visio/windows.xml":                 windowsXML,
		"visio/_rels/document.xml.rels":     documentRels,
		"visio/pages/pages.xml":             pagesXML,
		"visio/pages/_rels/pages.xml.rels": pagesRels,
		"visio/pages/page1.xml":             pageXML,
	}

	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			return nil, fmt.Errorf("failed creating entry %s in vsdx zip: %w", name, err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			return nil, fmt.Errorf("failed writing entry %s in vsdx zip: %w", name, err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("failed closing vsdx zip: %w", err)
	}

	return buf.Bytes(), nil
}
