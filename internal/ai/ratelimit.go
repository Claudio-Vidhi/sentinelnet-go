package ai

import (
	"sync"
	"time"
)

// rateLimiter: finestra scorrevole in-process, thread-safe (porta di
// RateLimiter). rpm<=0 disabilita il limite.
type rateLimiter struct {
	mu    sync.Mutex
	rpm   int
	stamp []time.Time
}

func (r *rateLimiter) configure(rpm int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rpm < 0 {
		rpm = 0
	}
	r.rpm = rpm
}

func (r *rateLimiter) currentRPM() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rpm
}

// allow: (true, 0) se ammessa ora; altrimenti (false, attesa consigliata).
func (r *rateLimiter) allow() (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rpm <= 0 {
		return true, 0
	}
	now := time.Now()
	windowStart := now.Add(-60 * time.Second)
	i := 0
	for i < len(r.stamp) && r.stamp[i].Before(windowStart) {
		i++
	}
	r.stamp = r.stamp[i:]
	if len(r.stamp) >= r.rpm {
		retry := 60*time.Second - now.Sub(r.stamp[0])
		if retry < 0 {
			retry = 0
		}
		return false, retry
	}
	r.stamp = append(r.stamp, now)
	return true, 0
}

// Limiter globale condiviso da tutte le Chat del processo.
var pkgRateLimiter = &rateLimiter{}

// ConfigureRateLimit imposta il limite globale richieste/minuto (0 = illimitato).
func ConfigureRateLimit(rpm int) { pkgRateLimiter.configure(rpm) }
