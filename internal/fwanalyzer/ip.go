// Package fwanalyzer: analizzatori firewall per-vendor (FortiOS, PAN-OS).
//
// Foglia: nessun import interno al progetto, per evitare cicli — è
// configanalyzer a importare questo, non il contrario. Porta di
// fw_analyzers/ del Python.
//
// Ogni analizzatore ritorna l'envelope generico {vendor, sections}, la stessa
// forma che il frontend rende in modo agnostico. Puro e tollerante: analyze
// non solleva mai — su input strano ritorna un envelope vuoto.
package fwanalyzer

import (
	"strconv"
	"strings"
)

// maskToPrefix converte una mask dotted (255.255.255.0) in lunghezza /nn.
// Ritorna -1 se non è una mask valida (es. già /nn o wildcard).
func maskToPrefix(mask string) int {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return -1
	}
	bits := 0
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return -1
		}
		bits += popcount(byte(v))
	}
	return bits
}

func popcount(b byte) int {
	n := 0
	for b != 0 {
		n += int(b & 1)
		b >>= 1
	}
	return n
}

// prefixToMask converte una lunghezza prefisso (0-32) in mask dotted.
// Stringa vuota se non valida. Usato dai converter.
func prefixToMask(pfx string) string {
	n, err := strconv.Atoi(pfx)
	if err != nil || n < 0 || n > 32 {
		return ""
	}
	var v uint32
	if n > 0 {
		v = uint32((0xFFFFFFFF << uint(32-n)) & 0xFFFFFFFF)
	}
	return strconv.Itoa(int((v>>24)&0xFF)) + "." + strconv.Itoa(int((v>>16)&0xFF)) + "." +
		strconv.Itoa(int((v>>8)&0xFF)) + "." + strconv.Itoa(int(v&0xFF))
}

// cidrSplit scinde "a.b.c.d/nn" in (ip, mask dotted). ("", "") se non valido.
func cidrSplit(cidr string) (string, string) {
	if cidr == "" || !strings.Contains(cidr, "/") {
		return "", ""
	}
	i := strings.Index(cidr, "/")
	ip, pfx := cidr[:i], cidr[i+1:]
	mask := prefixToMask(pfx)
	if mask == "" {
		return "", ""
	}
	return ip, mask
}

// ipAddrToCidr ricava "a.b.c.d/nn" da token tipo ["10.1.10.1","255.255.255.0"].
// Stringa vuota se non interpretabile.
func ipAddrToCidr(tokens []string) string {
	if len(tokens) >= 2 {
		ip := tokens[0]
		if pfx := maskToPrefix(tokens[1]); pfx >= 0 {
			return ip + "/" + strconv.Itoa(pfx)
		}
		if strings.HasPrefix(tokens[1], "/") {
			return ip + tokens[1]
		}
	}
	if len(tokens) == 1 && strings.Contains(tokens[0], "/") {
		return tokens[0]
	}
	return ""
}
