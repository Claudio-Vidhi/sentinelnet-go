package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/export"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/topology"
)

func (a *App) scopeAndGroup(r *http.Request) ([]string, string) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	group := r.URL.Query().Get("group")
	return scoped, group
}

// /api/topology → {links: [{source, target}]} (adjacency list testuale).
func (a *App) handleTopology(w http.ResponseWriter, r *http.Request) {
	scoped, group := a.scopeAndGroup(r)
	_, links, err := a.buildGraph(scoped, group)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]string, 0, len(links))
	for _, l := range links {
		out = append(out, map[string]string{"source": l.Source, "target": l.Target})
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// /api/network-map → {nodes, links} per la mappa 2D Vis.js.
func (a *App) handleNetworkMap(w http.ResponseWriter, r *http.Request) {
	scoped, group := a.scopeAndGroup(r)
	nodes, links, err := a.buildGraph(scoped, group)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "links": links})
}

// /api/portchannels → aggregati per switch con stato e vicini.
func (a *App) handlePortchannels(w http.ResponseWriter, r *http.Request) {
	scoped, group := a.scopeAndGroup(r)
	nodes, links, err := a.buildGraph(scoped, group)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	nodeByID := map[string]*Node{}
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	topoRows, err := a.store.ListTopology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	type pcOut struct {
		Name      string   `json:"name"`
		Members   []string `json:"members"`
		Neighbors []string `json:"neighbors"`
		Status    string   `json:"status"`
		Up        int      `json:"up"`
		Total     int      `json:"total"`
		Issue     bool     `json:"issue"`
		IssueMsg  string   `json:"issue_msg"`
	}
	type devOut struct {
		IP           string  `json:"ip"`
		Hostname     string  `json:"hostname"`
		Group        string  `json:"group"`
		PortChannels []pcOut `json:"portchannels"`
	}

	var out []devOut
	for _, row := range topoRows {
		n, ok := nodeByID[row.IP]
		if !ok {
			continue // fuori scope
		}
		var pcs []topology.PortChannel
		_ = json.Unmarshal([]byte(row.PortChannelsJSON), &pcs)
		if len(pcs) == 0 {
			continue
		}
		d := devOut{IP: row.IP, Hostname: n.Label, Group: n.Group}
		for _, pc := range pcs {
			po := pcOut{
				Name: pc.Name, Members: pc.Members,
				Total: len(pc.Members), Up: len(pc.Members), Status: "up",
			}
			// Vicini raggiunti tramite le interfacce membro del port-channel.
			// Il link può avere lo switch su ENTRAMBI i lati (source o target).
			for _, l := range links {
				var otherID string
				var myPorts []string
				switch row.IP {
				case l.Source:
					otherID, myPorts = l.Target, l.LocalPorts
				case l.Target:
					otherID, myPorts = l.Source, l.RemotePorts
				default:
					continue
				}
				if portsOverlap(myPorts, pc.Members) {
					if t, ok := nodeByID[otherID]; ok {
						po.Neighbors = appendUniq(po.Neighbors, t.Label)
					}
				}
			}
			d.PortChannels = append(d.PortChannels, po)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

func (a *App) handleTopologyReset(w http.ResponseWriter, _ *http.Request) {
	deleted, err := a.store.ClearTopology()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

// /api/device-classification → categorie, nodi, conteggi, vendor, modelli.
func (a *App) handleClassification(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	nodes, _, err := a.buildGraph(scoped, "all")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cats, err := a.store.ListCategories()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	vendors, err := a.store.ListVendors()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	models, err := a.store.ListModels()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	countsByCat := map[string]int{}
	countsByGroup := map[string]int{}
	for _, n := range nodes {
		countsByCat[n.DeviceType]++
		countsByGroup[n.Group]++
	}
	vendorNames := make([]string, 0, len(vendors))
	for v := range vendors {
		vendorNames = append(vendorNames, v)
	}
	sort.Strings(vendorNames)

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Group != nodes[j].Group {
			return nodes[i].Group < nodes[j].Group
		}
		return strings.ToLower(nodes[i].Label) < strings.ToLower(nodes[j].Label)
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"categories":         cats,
		"nodes":              nodes,
		"counts_by_category": countsByCat,
		"counts_by_group":    countsByGroup,
		"vendors":            vendorNames,
		"models":             models,
	})
}

type createCatReq struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Subcategory string `json:"subcategory"`
}

func (a *App) handleCreateCategory(w http.ResponseWriter, r *http.Request) {
	var req createCatReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	req.Key = strings.ToLower(strings.TrimSpace(req.Key))
	if req.Key == "" {
		writeErr(w, http.StatusBadRequest, "chiave categoria obbligatoria")
		return
	}
	if err := a.store.CreateCategory(req.Key, strings.TrimSpace(req.Label)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sub := strings.TrimSpace(req.Subcategory); sub != "" {
		if err := a.store.AddSubcategory(req.Key, sub); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type keyReq struct {
	Key string `json:"key"`
}

func (a *App) handleDeleteCategory(w http.ResponseWriter, r *http.Request) {
	var req keyReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := a.store.DeleteCategory(req.Key); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type delSubReq struct {
	Key         string `json:"key"`
	Subcategory string `json:"subcategory"`
}

func (a *App) handleDeleteSubcategory(w http.ResponseWriter, r *http.Request) {
	var req delSubReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if err := a.store.DeleteSubcategory(req.Key, req.Subcategory); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type assignReq struct {
	NodeID      string  `json:"node_id"`
	Category    *string `json:"category"`
	Subcategory *string `json:"subcategory"`
	Vendor      *string `json:"vendor"`
	Model       *string `json:"model"`
	HAGroup     *string `json:"ha_group"`
	Name        *string `json:"name"`
	Version     *string `json:"version"`
}

func (a *App) handleAssignCategory(w http.ResponseWriter, r *http.Request) {
	var req assignReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.NodeID == "" {
		writeErr(w, http.StatusBadRequest, "node_id obbligatorio")
		return
	}
	fields := map[string]string{}
	put := func(key string, p *string) {
		if p != nil {
			fields[key] = strings.TrimSpace(*p)
		}
	}
	put("category", req.Category)
	put("subcategory", req.Subcategory)
	put("vendor", req.Vendor)
	put("model", req.Model)
	put("ha_group", req.HAGroup)
	put("name", req.Name)
	put("version", req.Version)

	// Se assegnano un modello con vendor, cataloga anche il modello.
	if req.Model != nil && req.Vendor != nil {
		v := strings.ToLower(strings.TrimSpace(*req.Vendor))
		m := strings.TrimSpace(*req.Model)
		if v != "" && m != "" {
			_ = a.store.AddModel(v, m)
		}
	}
	if err := a.store.AssignMeta(req.NodeID, fields); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type promoteReq struct {
	NodeID     string `json:"node_id"`
	IP         string `json:"ip"`
	Vendor     string `json:"vendor"`
	Group      string `json:"group"`
	Model      string `json:"model"`
	Version    string `json:"version"`
	DeviceType string `json:"device_type"`
	Hostname   string `json:"hostname"`
}

// handlePromoteDevice: un vicino scoperto diventa dispositivo gestito.
func (a *App) handlePromoteDevice(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req promoteReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}
	if req.IP == "" {
		writeErr(w, http.StatusBadRequest, "IP annunciato mancante")
		return
	}
	if req.Group == "" {
		req.Group = "Generale"
	}
	scoped, _ := a.tenantsForUser(claims.Username, claims.Role)
	if !canSeeTenant(scoped, req.Group) {
		writeErr(w, http.StatusForbidden, "tenant non consentito")
		return
	}
	if req.Vendor == "" || req.Vendor == "discovered" {
		req.Vendor = "cisco"
	}
	if err := a.store.UpsertDeviceForPromotion(req.IP, strings.ToLower(req.Vendor), req.Group, req.Hostname); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if req.Version != "" {
		_ = a.store.UpsertVersion(req.IP, strings.ToLower(req.Vendor), req.Version, "offline")
	}
	// Trasferisci la classificazione manuale dal nodo scoperto all'IP gestito.
	fields := map[string]string{}
	if req.DeviceType != "" {
		fields["category"] = req.DeviceType
	}
	if req.Model != "" {
		fields["model"] = req.Model
	}
	if len(fields) > 0 {
		_ = a.store.AssignMeta(req.IP, fields)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type visioExportReq struct {
	Nodes      []export.VisioNode       `json:"nodes"`
	Edges      []export.VisioEdge       `json:"edges"`
	Primitives *export.VisioPrimitives `json:"primitives"`
	Connectors []export.VisioConnector  `json:"connectors"`
}

func (a *App) handleExportMapVSDX(w http.ResponseWriter, r *http.Request) {
	claims := claimsFrom(r.Context())
	var req visioExportReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "payload non valido")
		return
	}

	data, err := export.BuildVSDX(req.Nodes, req.Edges, req.Primitives, req.Connectors)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.auditLog("Export Visio mappa richiesto dall'utente '" + claims.Username + "'.")
	w.Header().Set("Content-Type", "application/vnd.ms-visio.drawing")
	w.Header().Set("Content-Disposition", "attachment; filename=sentinelnet-map.vsdx")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
