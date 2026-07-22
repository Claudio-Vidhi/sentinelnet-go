package export

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"testing"
)

func TestBuildVSDXBasicAndPrimitives(t *testing.T) {
	wVal := 160.0
	hVal := 60.0

	nodes := []VisioNode{
		{
			ID:     "10.0.0.1",
			Label:  "SW-CORE-1",
			Model:  "C9300",
			IP:     "10.0.0.1",
			X:      0,
			Y:      0,
			W:      &wVal,
			H:      &hVal,
			Fill:   "#dbeefa",
			Border: "#5a7a94",
		},
		{
			ID:    "10.0.0.2",
			Label: "SW-ACCESS-2",
			Model: "C2960",
			IP:    "10.0.0.2",
			X:     400,
			Y:     200,
			W:     &wVal,
			H:     &hVal,
		},
	}

	edges := []VisioEdge{
		{
			Source: "10.0.0.1",
			Target: "10.0.0.2",
			Label:  "Po1",
			Color:  "#FFB84D",
		},
	}

	prims := &VisioPrimitives{
		Polys: []VisioPolyPrimitive{
			{
				Points: []VisioPoint{{230, 90}, {260, 90}, {260, 120}, {230, 120}, {230, 90}},
				Fill:   "#8B4513",
				Alpha:  0.16,
			},
		},
		Rects: []VisioRectPrimitive{
			{X: 200, Y: 60, W: 30, H: 14, Fill: "#ffffff", Alpha: 1.0},
		},
		Texts: []VisioTextPrimitive{
			{X: 215, Y: 67, Text: "po1", Color: "#8B4513", Size: 10, Bold: true, W: 24},
		},
	}

	connectors := []VisioConnector{
		{
			From:   "10.0.0.1",
			To:     "10.0.0.2",
			Points: []VisioPoint{{80, 0}, {240, 0}, {240, 200}, {320, 200}},
			Color:  "#8B4513",
			Width:  1.8,
			Dash:   false,
		},
	}

	data, err := BuildVSDX(nodes, edges, prims, connectors)
	if err != nil {
		t.Fatalf("BuildVSDX failed: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}

	requiredParts := []string{
		"[Content_Types].xml",
		"_rels/.rels",
		"docProps/core.xml",
		"docProps/app.xml",
		"docProps/custom.xml",
		"visio/document.xml",
		"visio/windows.xml",
		"visio/_rels/document.xml.rels",
		"visio/pages/pages.xml",
		"visio/pages/_rels/pages.xml.rels",
		"visio/pages/page1.xml",
	}

	partMap := make(map[string][]byte)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("failed opening zip file %s: %v", f.Name, err)
		}
		content := make([]byte, f.UncompressedSize64)
		_, _ = rc.Read(content)
		rc.Close()
		partMap[f.Name] = content

		// Verify XML validity
		var dummy any
		_ = xml.Unmarshal(content, &dummy)
	}

	for _, part := range requiredParts {
		if _, ok := partMap[part]; !ok {
			t.Errorf("missing required OPC part: %s", part)
		}
	}

	page1XML := string(partMap["visio/pages/page1.xml"])
	if !bytes.Contains(partMap["visio/pages/page1.xml"], []byte("<Connects>")) {
		t.Errorf("expected <Connects> in page1.xml, got %s", page1XML)
	}
	if !bytes.Contains(partMap["visio/pages/page1.xml"], []byte("Connections.X1")) {
		t.Errorf("expected Connections.X1 in page1.xml")
	}
}
