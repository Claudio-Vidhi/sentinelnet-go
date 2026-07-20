package observability

import (
	"sync"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/observability/ingest"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/obsstore"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

const syslogInsertSQL = `
INSERT INTO syslog_events (ts, tenant, device_ip, severity, action, message, exporter_ip)
VALUES (?, ?, ?, ?, ?, ?, ?)`

const quarantineUpsertSQL = `
INSERT INTO quarantined_exporters (exporter_ip, first_seen, last_seen, packet_count)
VALUES (?, ?, ?, 1)
ON CONFLICT(exporter_ip) DO UPDATE SET
    last_seen = excluded.last_seen,
    packet_count = packet_count + 1`

// storeSink consegna i record decodificati alla coda del writer.
type storeSink struct{ obs *obsstore.Store }

func (s storeSink) WriteFlow(tenant string, rec ingest.FlowRecord, receiveTS int64, source string) {
	s.obs.EnqueueFlow(obsstore.Flow{
		Tenant: tenant, SrcIP: rec.SrcIP, DstIP: rec.DstIP,
		Protocol: rec.Protocol, DstPort: rec.DstPort,
		TotalBytes: rec.Bytes, TotalPackets: rec.Packets,
		ExporterIP: rec.ExporterIP, Source: source,
		ExportTS: rec.FlowEndTS, ReceiveTS: receiveTS,
	})
}

func (s storeSink) WriteSyslog(tenant string, ev ingest.SyslogEvent) {
	s.obs.EnqueueWrite(syslogInsertSQL,
		ev.TS, tenant, ev.DeviceIP, obsstore.NullIfNegative(ev.Severity),
		ev.Action, ev.Message, ev.ExporterIP)
}

func (s storeSink) Quarantine(exporterIP string, ts int64) {
	s.obs.EnqueueWrite(quarantineUpsertSQL, exporterIP, ts, ts)
}

// tenantCacheTTL limita la frequenza delle query di inventario nel percorso
// di ingest.
const tenantCacheTTL = 60 * time.Second

// storeResolver risolve l'IP di un exporter nel tenant del device.
//
// La risoluzione avviene per ogni record decodificato, quindi migliaia di
// volte al secondo sotto carico: senza cache ogni flusso costerebbe una query
// su SQLite, in contesa con il writer. Il Python usa una cache invalidata a
// ogni modifica dell'inventario; qui basta un TTL breve, che non richiede di
// agganciarsi a tutti i punti di scrittura e ha lo stesso effetto pratico
// (un device appena aggiunto viene riconosciuto entro un minuto).
type storeResolver struct {
	st  *store.Store
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	cached map[string]cachedTenant
}

type cachedTenant struct {
	tenant string
	known  bool
	at     time.Time
}

func newStoreResolver(st *store.Store) *storeResolver {
	return &storeResolver{st: st, ttl: tenantCacheTTL, now: time.Now, cached: map[string]cachedTenant{}}
}

func (r *storeResolver) TenantForIP(ip string) (string, bool) {
	now := r.now()

	r.mu.Lock()
	if e, ok := r.cached[ip]; ok && now.Sub(e.at) < r.ttl {
		r.mu.Unlock()
		return e.tenant, e.known
	}
	r.mu.Unlock()

	tenant, known := "", false
	if d, err := r.st.GetDevice(ip); err == nil && d != nil {
		tenant, known = d.Tenant, true
	}

	r.mu.Lock()
	r.cached[ip] = cachedTenant{tenant: tenant, known: known, at: now}
	r.mu.Unlock()
	return tenant, known
}
