package obsstore

import (
	"fmt"
	"time"
)

// BatchRows: righe eliminate per transazione. I DELETE sono batchati per non
// tenere lock lunghi sul database mentre il writer sta scrivendo.
const BatchRows = 5000

// pruneTable descrive come si applica la retention a una tabella.
type pruneTable struct {
	name    string
	tsCol   string
	extraWh string
}

// Gli eventi correlati non risolti (status new/ack) non vengono MAI eliminati
// automaticamente: sono segnalazioni ancora aperte.
var pruneTables = []pruneTable{
	{"flow_aggregates", "window_start", ""},
	{"syslog_events", "ts", ""},
	{"correlated_events", "created_ts", " AND status = 'resolved'"},
}

// RetentionDays è la finestra di conservazione per tabella, in giorni.
// Un valore <= 0 disattiva la retention per quella tabella.
type RetentionDays struct {
	FlowAggregates   int `json:"flow_aggregates"`
	SyslogEvents     int `json:"syslog_events"`
	CorrelatedEvents int `json:"correlated_events"`
}

func (r RetentionDays) daysFor(table string) int {
	switch table {
	case "flow_aggregates":
		return r.FlowAggregates
	case "syslog_events":
		return r.SyslogEvents
	case "correlated_events":
		return r.CorrelatedEvents
	}
	return 0
}

// PruneOnce elimina le righe più vecchie della finestra configurata e ritorna
// il numero di righe eliminate per tabella.
//
// Misura tecnica di minimizzazione: i dati di osservabilità contengono indirizzi
// IP, quindi non vanno conservati oltre il necessario.
func (s *Store) PruneOnce(retention RetentionDays, now time.Time) (map[string]int64, error) {
	deleted := map[string]int64{}
	nowUnix := now.Unix()

	for _, t := range pruneTables {
		days := retention.daysFor(t.name)
		if days <= 0 {
			continue
		}
		cutoff := nowUnix - int64(days)*86400
		// #nosec G201 — nome tabella e colonna vengono da pruneTables, non da input.
		query := fmt.Sprintf(
			`DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE %s < ?%s LIMIT ?)`,
			t.name, t.name, t.tsCol, t.extraWh)

		var total int64
		for {
			res, err := s.DB.Exec(query, cutoff, BatchRows)
			if err != nil {
				return deleted, err
			}
			n, _ := res.RowsAffected()
			total += n
			if n < BatchRows {
				break
			}
		}
		if total > 0 {
			deleted[t.name] = total
		}
	}
	s.Metrics.SetGauge("last_prune_ts", nowUnix)
	return deleted, nil
}
