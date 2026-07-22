# Design — Visio Export (.vsdx Generator)

Porta il modulo `services/visio_export.py` dall'app Python verso il server Go (`internal/export/visio.go` e l'endpoint `POST /api/map/export/vsdx` in `internal/api`).

## Obiettivo

Costruire un file `.vsdx` (Microsoft Visio) nativo ed editiabile direttamente in memoria usando esclusivamente la libreria standard Go (`archive/zip` e `bytes.Buffer`).

- **Senza dipendenze esterne**: `.vsdx` è un archivio ZIP OPC contenente strutture XML (pagine, forme 2-D per i dispositivi, forme 1-D per i collegamenti ortogonali, e punti di ancoraggio `Connection` + `Connects` per il glue dinamico).
- **Parità 1:1 con il Python**: replica l'algoritmo di conversione coordinate (scala `_SCALE = 0.02`), il calcolo dei bounds, la registrazione degli anchor `Connection`, la gestione dei quadratini colorati figli del gruppo e la generazione di tutti i file OPC (`[Content_Types].xml`, `_rels/.rels`, `visio/document.xml`, `visio/pages/page1.xml`, ecc.).
- **Endpoint HTTP**: `POST /api/map/export/vsdx` risponde con il binario `application/vnd.ms-visio.drawing` e l'header `Content-Disposition: attachment; filename=sentinelnet-map.vsdx`.

## Tipi Go (`internal/export/visio.go`)

```go
type VisioNode struct {
	ID     string  `json:"id"`
	Label  string  `json:"label"`
	Model  string  `json:"model"`
	IP     string  `json:"ip"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	W      *float64`json:"w,omitempty"`
	H      *float64`json:"h,omitempty"`
	Fill   string  `json:"fill,omitempty"`
	Border string  `json:"border,omitempty"`
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
```

## Funzione Principale

```go
func BuildVSDX(nodes []VisioNode, edges []VisioEdge, primitives *VisioPrimitives, connectors []VisioConnector) ([]byte, error)
```

## API Endpoint (`internal/api/topology_handlers.go`)

- `POST /api/map/export/vsdx` (utente autenticato)
  - Content-Type: `application/vnd.ms-visio.drawing`
  - Header: `Content-Disposition: attachment; filename=sentinelnet-map.vsdx`
