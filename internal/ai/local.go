// Package ai: astrazione verso i provider LLM (porta di ai/ai_assistant.py).
// Libreria: nessuna rotta HTTP. Il choke-point di redazione (finding I-1) vive
// in Chat.
package ai

import (
	"net"
	"net/url"
	"strings"
)

// IsLocalBaseURL: true se l'host del base_url è locale/privato (loopback o
// RFC1918). Porta di _is_local_base_url.
func IsLocalBaseURL(baseURL string) bool {
	if baseURL == "" {
		return false
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
