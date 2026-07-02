// Package euvd: proxy verso l'API ENISA EUVD (whitelist parametri, size cap 100).
package euvd

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"
)

const baseURL = "https://euvdservices.enisa.europa.eu/api/search"

var allowedParams = map[string]bool{
	"text": true, "vendor": true, "product": true,
	"page": true, "size": true, "fromScore": true, "toScore": true,
}

var client = &http.Client{Timeout: 15 * time.Second}

// Search inoltra i parametri consentiti a EUVD e restituisce il corpo grezzo JSON.
func Search(ctx context.Context, in url.Values) ([]byte, int, error) {
	out := url.Values{}
	for k, vs := range in {
		if !allowedParams[k] {
			continue
		}
		out[k] = vs
	}
	// cap size a 100
	if out.Get("size") == "" {
		out.Set("size", "10")
	} else if n := atoiClamp(out.Get("size"), 1, 100); n > 0 {
		out.Set("size", itoa(n))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"?"+out.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SentinelNet/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return body, resp.StatusCode, err
}

func atoiClamp(s string, lo, hi int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > hi {
			return hi
		}
	}
	if n < lo {
		return lo
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
