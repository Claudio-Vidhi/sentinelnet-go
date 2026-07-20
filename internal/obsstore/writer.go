package obsstore

import (
	"time"
)

const (
	QueueMax     = 10_000 // scritture massime in coda
	BatchSize    = 500    // scritture massime per singolo commit
	ClockSkewMax = 300    // tolleranza timestamp exporter, in secondi
)

type writeJob struct {
	sql  string
	args []any
	// done, se non nil, viene chiuso dopo il commit del batch che contiene
	// questo job. Un job con sql vuoto è una sola barriera di sincronizzazione.
	done chan struct{}
}

// Sync attende che tutte le scritture accodate finora siano state committate.
// Serve nei test e prima di leggere ciò che si è appena scritto.
func (s *Store) Sync() {
	done := make(chan struct{})
	select {
	case s.queue <- writeJob{done: done}:
	case <-s.closed:
		return
	}
	select {
	case <-done:
	case <-s.closed:
	}
}

// EnqueueWrite accoda una scrittura. Non blocca mai: se la coda è piena la
// scrittura viene scartata con metrica, perché l'ingest UDP non deve
// rallentare in attesa del disco. Ritorna false se scartata.
func (s *Store) EnqueueWrite(sql string, args ...any) bool {
	select {
	case s.queue <- writeJob{sql: sql, args: args}:
		return true
	default:
		s.Metrics.Inc("writes_dropped_queue_full")
		return false
	}
}

const flowUpsertSQL = `
INSERT INTO flow_aggregates
    (window_start, tenant, src_ip, dst_ip, protocol, dst_port,
     total_bytes, total_packets, flow_count, exporter_ip, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
ON CONFLICT(window_start, tenant, src_ip, dst_ip, protocol, dst_port)
DO UPDATE SET
    total_bytes   = total_bytes   + excluded.total_bytes,
    total_packets = total_packets + excluded.total_packets,
    flow_count    = flow_count    + 1,
    exporter_ip   = excluded.exporter_ip,
    source        = excluded.source`

// Flow è un flusso normalizzato pronto per l'aggregazione al minuto.
type Flow struct {
	Tenant       string
	SrcIP        string
	DstIP        string
	Protocol     int
	DstPort      int
	TotalBytes   int64
	TotalPackets int64
	ExporterIP   string
	Source       string // ipfix | netflow | sflow
	ExportTS     int64  // 0 = assente
	ReceiveTS    int64  // 0 = adesso
}

// EnqueueFlow accoda l'UPSERT di aggregazione al minuto per un flusso.
func (s *Store) EnqueueFlow(f Flow) bool {
	return s.EnqueueWrite(flowUpsertSQL,
		s.FlowWindowStart(f.ExportTS, f.ReceiveTS), f.Tenant, f.SrcIP, f.DstIP,
		NullIfNegative(f.Protocol), NullIfNegative(f.DstPort),
		f.TotalBytes, f.TotalPackets, f.ExporterIP, f.Source)
}

// NullIfNegative traduce il "campo assente" dei decoder (-1) in NULL.
// Il Python emette None per gli stessi casi e le colonne sono nullable:
// scrivere 0 renderebbe indistinguibile "protocollo 0" da "protocollo ignoto".
func NullIfNegative(v int) any {
	if v < 0 {
		return nil
	}
	return v
}

// FlowWindowStart calcola il bucket al minuto di un flusso: usa il timestamp
// dell'exporter se entro ±ClockSkewMax dalla ricezione, altrimenti il tempo di
// ricezione (contatore clock_skew_fallback).
//
// Serve perché gli exporter con orologio sbagliato altrimenti scriverebbero in
// finestre lontanissime, rendendo inutilizzabili le query per intervallo.
func (s *Store) FlowWindowStart(exportTS, receiveTS int64) int64 {
	now := receiveTS
	if now == 0 {
		now = time.Now().Unix()
	}
	ts := exportTS
	if ts == 0 || abs64(ts-now) > ClockSkewMax {
		if ts != 0 {
			s.Metrics.Inc("clock_skew_fallback")
		}
		ts = now
	}
	return ts - (ts % 60)
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// writerLoop consuma la coda: una sola goroutine scrive, con commit a batch.
func (s *Store) writerLoop() {
	defer close(s.closed)
	for {
		select {
		case job := <-s.queue:
			s.flush(s.drain(job))
		case <-s.done:
			// Svuota ciò che resta prima di uscire.
			for {
				select {
				case job := <-s.queue:
					s.flush(s.drain(job))
				default:
					return
				}
			}
		}
	}
}

// drain raccoglie fino a BatchSize scritture già disponibili, senza attendere.
func (s *Store) drain(first writeJob) []writeJob {
	batch := make([]writeJob, 0, BatchSize)
	batch = append(batch, first)
	for len(batch) < BatchSize {
		select {
		case job := <-s.queue:
			batch = append(batch, job)
		default:
			return batch
		}
	}
	return batch
}

// flush esegue un batch in una sola transazione. Un errore su una singola
// scrittura non deve far cadere l'intero batch né il writer: si conta e si
// prosegue, perché l'applicazione deve restare viva anche se l'osservabilità
// perde dati.
func (s *Store) flush(batch []writeJob) {
	if len(batch) == 0 {
		return
	}
	// Le barriere di Sync vanno sbloccate comunque vada il commit.
	defer func() {
		for _, job := range batch {
			if job.done != nil {
				close(job.done)
			}
		}
	}()

	tx, err := s.DB.Begin()
	if err != nil {
		s.Metrics.Add("writes_dropped_error", int64(len(batch)))
		return
	}
	ok := 0
	for _, job := range batch {
		if job.sql == "" {
			continue // barriera di sincronizzazione, non una scrittura
		}
		if _, err := tx.Exec(job.sql, job.args...); err != nil {
			s.Metrics.Inc("writes_dropped_error")
			continue
		}
		ok++
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		s.Metrics.Add("writes_dropped_error", int64(ok))
		return
	}
	s.Metrics.Add("writes_ok", int64(ok))
}
