// Package observability: gestione del ciclo di vita della pipeline di
// osservabilità — listener UDP, task periodici e configurazione applicabile
// a caldo. Porta di observability/listener_manager.go e rollup.py.
package observability

import "github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"

// ListenerConfig abilita un singolo protocollo su una porta.
type ListenerConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// Config è la configurazione desiderata della pipeline. Corrisponde campo per
// campo al corpo di GET/POST /api/observability/config.
type Config struct {
	Enabled       bool                   `json:"enabled"`
	Bind          string                 `json:"bind"`
	IPFIX         ListenerConfig         `json:"ipfix"`
	SFlow         ListenerConfig         `json:"sflow"`
	Syslog        ListenerConfig         `json:"syslog"`
	NetFlow       ListenerConfig         `json:"netflow"`
	APIPollS      int                    `json:"api_poll_s"`
	RetentionDays obsstore.RetentionDays `json:"retention_days"`
}

// DefaultConfig replica i default del Python.
func DefaultConfig() Config {
	return Config{
		Enabled:  false,
		Bind:     "0.0.0.0",
		IPFIX:    ListenerConfig{Port: 4739},
		SFlow:    ListenerConfig{Port: 6343},
		Syslog:   ListenerConfig{Port: 5514},
		NetFlow:  ListenerConfig{Port: 2055},
		APIPollS: 300,
		RetentionDays: obsstore.RetentionDays{
			FlowAggregates:   30,
			SyslogEvents:     7,
			CorrelatedEvents: 90,
		},
	}
}

// ListenerStatus è lo stato osservabile di un listener, esposto da
// /api/observability/config e /api/observability/health.
type ListenerStatus struct {
	Active bool   `json:"active"`
	Bind   string `json:"bind,omitempty"`
	Port   int    `json:"port,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ValidPort vale per le porte accettate dalla configurazione.
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }
