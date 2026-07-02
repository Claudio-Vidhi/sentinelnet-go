package api

import (
	"net/http"
	"net/url"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/euvd"
)

// handleEUVDSearch: proxy verso ENISA EUVD. Se il parametro "vendor" è un nome
// noto, lo traduce nel termine EUVD registrato (es. cisco→cisco).
func (a *App) handleEUVDSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := url.Values{}
	if text := q.Get("text"); text != "" {
		params.Set("text", text)
	}
	if size := q.Get("size"); size != "" {
		params.Set("size", size)
	}
	// Risoluzione del vendor nel termine EUVD.
	if vendor := q.Get("vendor"); vendor != "" {
		term := vendor
		if vendors, err := a.store.ListVendors(); err == nil {
			if meta, ok := vendors[vendor]; ok && meta.EUVDTerm != "" {
				term = meta.EUVDTerm
			}
		}
		params.Set("vendor", term)
	}

	body, status, err := euvd.Search(r.Context(), params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "EUVD non raggiungibile: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}
