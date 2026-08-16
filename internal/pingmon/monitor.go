// Package pingmon: monitoraggio ICMP continuo dei dispositivi censiti in inventario.
// Porta di services/ping_monitor.py.
package pingmon

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

const (
	DefaultInterval = 60
	MinInterval     = 5
	MaxInterval     = 86400
	SettingKey      = "ping_monitor"
)

type Config struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
}

type DeviceState struct {
	IP         string  `json:"ip"`
	Up         bool    `json:"up"`
	LastCheck  int64   `json:"last_check"`
	LastChange int64   `json:"last_change"`
	Checks     int     `json:"checks"`
	Fails      int     `json:"fails"`
	RTTMs      float64 `json:"rtt_ms,omitempty"`
}

type Summary struct {
	Total int `json:"total"`
	Up    int `json:"up"`
	Down  int `json:"down"`
}

type StatusResponse struct {
	Enabled         bool          `json:"enabled"`
	IntervalSeconds int           `json:"interval_seconds"`
	LastRun         *int64        `json:"last_run,omitempty"`
	Devices         []DeviceState `json:"devices"`
	Summary         Summary       `json:"summary"`
}

type Monitor struct {
	st       *store.Store
	auditFn  func(string)
	probeFn  func(context.Context, string) bool
	mu       sync.RWMutex
	state    map[string]*DeviceState
	lastRun  *int64
	wakeCh   chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}
	running  bool
}

func New(st *store.Store, auditFn func(string)) *Monitor {
	return &Monitor{
		st:      st,
		auditFn: auditFn,
		probeFn: collect.Ping,
		state:   make(map[string]*DeviceState),
		wakeCh:  make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// SetProbeFunc permette di sostituire la funzione di probe (per i test).
func (m *Monitor) SetProbeFunc(fn func(context.Context, string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.probeFn = fn
}

func (m *Monitor) GetConfig() Config {
	if m.st == nil {
		return Config{Enabled: false, IntervalSeconds: DefaultInterval}
	}
	raw := m.st.GetSetting(SettingKey, "{}")
	var cfg Config
	_ = json.Unmarshal([]byte(raw), &cfg)
	if cfg.IntervalSeconds < MinInterval {
		cfg.IntervalSeconds = DefaultInterval
	}
	if cfg.IntervalSeconds > MaxInterval {
		cfg.IntervalSeconds = MaxInterval
	}
	return cfg
}

func (m *Monitor) SaveConfig(enabled bool, intervalSeconds int, username string) (Config, error) {
	if intervalSeconds < MinInterval {
		intervalSeconds = MinInterval
	}
	if intervalSeconds > MaxInterval {
		intervalSeconds = MaxInterval
	}
	cfg := Config{Enabled: enabled, IntervalSeconds: intervalSeconds}
	b, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}
	if err := m.st.SetSetting(SettingKey, string(b)); err != nil {
		return cfg, err
	}

	action := "disattivato"
	if enabled {
		action = "attivato"
	}
	if m.auditFn != nil {
		m.auditFn("Ping monitor " + action + " (intervallo " + jsonNumber(intervalSeconds) + "s) da '" + username + "'.")
	}

	m.Wake()
	return cfg, nil
}

func (m *Monitor) Wake() {
	select {
	case m.wakeCh <- struct{}{}:
	default:
	}
}

func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	go m.loop()
}

func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	<-m.doneCh
}

func (m *Monitor) loop() {
	defer close(m.doneCh)

	for {
		cfg := m.GetConfig()
		if !cfg.Enabled {
			select {
			case <-m.stopCh:
				return
			case <-m.wakeCh:
				continue
			case <-time.After(2 * time.Second):
				continue
			}
		}

		m.RunCycle()

		select {
		case <-m.stopCh:
			return
		case <-m.wakeCh:
			continue
		case <-time.After(time.Duration(cfg.IntervalSeconds) * time.Second):
			continue
		}
	}
}

func (m *Monitor) RunCycle() {
	if m.st == nil {
		return
	}

	devices, err := m.st.ListDevices()
	if err != nil {
		return
	}

	ipsMap := map[string]bool{}
	for _, d := range devices {
		if d.IP != "" {
			ipsMap[d.IP] = true
		}
	}

	var ips []string
	for ip := range ipsMap {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	now := time.Now().Unix()
	if len(ips) == 0 {
		m.mu.Lock()
		m.state = make(map[string]*DeviceState)
		m.lastRun = &now
		m.mu.Unlock()
		return
	}

	type pingResult struct {
		ip string
		up bool
	}

	resCh := make(chan pingResult, len(ips))
	sem := make(chan struct{}, 50)
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	probe := m.probeFn
	if probe == nil {
		probe = collect.Ping
	}

	for _, ip := range ips {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			alive := probe(ctx, target)
			resCh <- pingResult{ip: target, up: alive}
		}(ip)
	}

	wg.Wait()
	close(resCh)

	m.mu.Lock()
	defer m.mu.Unlock()

	for res := range resCh {
		prev := m.state[res.ip]
		if prev == nil {
			fails := 0
			if !res.up {
				fails = 1
			}
			m.state[res.ip] = &DeviceState{
				IP:         res.ip,
				Up:         res.up,
				LastCheck:  now,
				LastChange: now,
				Checks:     1,
				Fails:      fails,
			}
		} else {
			if prev.Up != res.up {
				prev.LastChange = now
			}
			prev.Up = res.up
			prev.LastCheck = now
			prev.Checks++
			if !res.up {
				prev.Fails++
			}
		}
	}

	for ip := range m.state {
		if !ipsMap[ip] {
			delete(m.state, ip)
		}
	}
	m.lastRun = &now
}

func (m *Monitor) GetStatus(allowedTenants []string) StatusResponse {
	cfg := m.GetConfig()

	m.mu.RLock()
	defer m.mu.RUnlock()

	var ipFilter map[string]bool
	if allowedTenants != nil && m.st != nil {
		ipFilter = map[string]bool{}
		devs, err := m.st.ListDevices()
		if err == nil {
			tenantSet := map[string]bool{}
			for _, t := range allowedTenants {
				tenantSet[t] = true
			}
			for _, d := range devs {
				grp := d.Tenant
				if grp == "" {
					grp = "Generale"
				}
				if tenantSet[grp] {
					ipFilter[d.IP] = true
				}
			}
		}
	}

	var list []DeviceState
	upCount := 0

	for _, st := range m.state {
		if ipFilter != nil && !ipFilter[st.IP] {
			continue
		}
		list = append(list, *st)
		if st.Up {
			upCount++
		}
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].IP < list[j].IP
	})

	return StatusResponse{
		Enabled:         cfg.Enabled,
		IntervalSeconds: cfg.IntervalSeconds,
		LastRun:         m.lastRun,
		Devices:         list,
		Summary: Summary{
			Total: len(list),
			Up:    upCount,
			Down:  len(list) - upCount,
		},
	}
}

func jsonNumber(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
