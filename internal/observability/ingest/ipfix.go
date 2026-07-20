package ingest

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// Decoder NetFlow v5/v9 + IPFIX (RFC 7011).
//
// v9 e IPFIX sono basati su template: la struttura dei data record è annunciata
// in set separati, che possono arrivare dopo i dati a cui si riferiscono. Da qui
// i due elementi di stato: la cache dei template e il buffer dei data set in
// attesa.
//
// A differenza del Python, che tiene questo stato in variabili di modulo, qui è
// dentro una struct con mutex: più listener condividono il decoder e uno stato
// globale mutabile sarebbe una race.
const (
	MaxTemplates    = 1024
	TemplateTTL     = 1800 * time.Second
	MaxPendingSets  = 256
	maxV5Records    = 30
	varLengthMarker = 65535
)

// Information Element rilevanti (RFC 7012).
const (
	ieBytes   = 1
	iePackets = 2
	ieProto   = 4
	ieSrcPort = 7
	ieSrc4    = 8
	ieDstPort = 11
	ieDst4    = 12
	ieSrc6    = 27
	ieDst6    = 28
	ieEndSec  = 151
	ieEndMsec = 153
)

type templateKey struct {
	exporterIP string
	odid       uint32
	templateID uint16
}

type templateField struct {
	ie     int // negativo = IE enterprise, mai corrispondente a quelli noti
	length int // varLengthMarker = lunghezza variabile
}

type templateEntry struct {
	fields  []templateField
	created time.Time
}

type pendingSet struct {
	payload    []byte
	exporterIP string
	exportTS   int64
}

// ParseStats riporta al chiamante ciò che il Python contava direttamente sul
// registro delle metriche, così il decoder resta senza dipendenze.
type ParseStats struct {
	ParseErrors               int
	DataBeforeTemplateDropped int
}

type Decoder struct {
	mu        sync.Mutex
	templates map[templateKey]templateEntry
	pending   map[templateKey][]pendingSet
	pendingN  int
	now       func() time.Time
}

func NewDecoder() *Decoder {
	return &Decoder{
		templates: map[templateKey]templateEntry{},
		pending:   map[templateKey][]pendingSet{},
		now:       time.Now,
	}
}

// TemplateCacheSize è esposto dall'endpoint di health.
func (d *Decoder) TemplateCacheSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.templates)
}

// Parse decodifica un datagramma NetFlow v5/v9 o IPFIX.
func (d *Decoder) Parse(data []byte, exporterIP string) ([]FlowRecord, ParseStats) {
	var stats ParseStats
	if len(data) < 4 {
		return nil, stats
	}
	switch binary.BigEndian.Uint16(data[0:2]) {
	case 5:
		return d.parseV5(data, exporterIP), stats
	case 9:
		return d.parseV9(data, exporterIP, &stats), stats
	case 10:
		return d.parseIPFIX(data, exporterIP, &stats), stats
	default:
		stats.ParseErrors++
		return nil, stats
	}
}

// --- NetFlow v5 (formato fisso, senza template) ---

func (d *Decoder) parseV5(data []byte, exporterIP string) []FlowRecord {
	if len(data) < 24 {
		return nil
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	unixSecs := int64(binary.BigEndian.Uint32(data[8:12]))
	if count > maxV5Records {
		count = maxV5Records
	}

	var out []FlowRecord
	off := 24
	for i := 0; i < count; i++ {
		if off+48 > len(data) {
			break
		}
		r := data[off : off+48]
		src, _ := netip.AddrFromSlice(r[0:4])
		dst, _ := netip.AddrFromSlice(r[4:8])
		out = append(out, FlowRecord{
			SrcIP:      src.String(),
			DstIP:      dst.String(),
			Protocol:   int(r[38]),
			DstPort:    int(binary.BigEndian.Uint16(r[34:36])),
			Packets:    int64(binary.BigEndian.Uint32(r[16:20])), // dPkts
			Bytes:      int64(binary.BigEndian.Uint32(r[20:24])), // dOctets
			FlowEndTS:  unixSecs,
			ExporterIP: exporterIP,
		})
		off += 48
	}
	return out
}

// --- NetFlow v9 / IPFIX (basati su template) ---

func (d *Decoder) parseV9(data []byte, exporterIP string, stats *ParseStats) []FlowRecord {
	if len(data) < 20 {
		return nil
	}
	unixSecs := int64(binary.BigEndian.Uint32(data[8:12]))
	sourceID := binary.BigEndian.Uint32(data[16:20])
	return d.parseSets(data, 20, exporterIP, sourceID, unixSecs, 0, 1, false, stats)
}

func (d *Decoder) parseIPFIX(data []byte, exporterIP string, stats *ParseStats) []FlowRecord {
	if len(data) < 16 {
		return nil
	}
	exportTime := int64(binary.BigEndian.Uint32(data[4:8]))
	odid := binary.BigEndian.Uint32(data[12:16])
	return d.parseSets(data, 16, exporterIP, odid, exportTime, 2, 3, true, stats)
}

// parseSets percorre i set del datagramma. templateSetID e optionsSetID
// distinguono v9 (0/1) da IPFIX (2/3).
func (d *Decoder) parseSets(data []byte, off int, exporterIP string, odid uint32,
	exportTS int64, templateSetID, optionsSetID uint16, enterpriseCapable bool,
	stats *ParseStats) []FlowRecord {

	var out []FlowRecord
	for off+4 <= len(data) {
		setID := binary.BigEndian.Uint16(data[off : off+2])
		setLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(data) {
			break
		}
		payload := data[off+4 : off+setLen]

		switch {
		case setID == templateSetID:
			out = append(out, d.parseTemplateSet(payload, exporterIP, odid, enterpriseCapable)...)
		case setID == optionsSetID:
			// Options template: non usato.
		case setID > 255:
			key := templateKey{exporterIP, odid, setID}
			if fields := d.template(key); fields != nil {
				out = append(out, decodeDataSet(payload, fields, exporterIP, exportTS)...)
			} else {
				d.bufferPending(key, payload, exporterIP, exportTS, stats)
			}
		}
		off += setLen
	}
	return out
}

// parseTemplateSet registra i template annunciati e ritorna i record
// ri-decodificati dai data set che erano in attesa di quei template.
func (d *Decoder) parseTemplateSet(payload []byte, exporterIP string, odid uint32,
	enterpriseCapable bool) []FlowRecord {

	var out []FlowRecord
	off := 0
	for off+4 <= len(payload) {
		tid := binary.BigEndian.Uint16(payload[off : off+2])
		fieldCount := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
		off += 4

		fields := make([]templateField, 0, fieldCount)
		ok := true
		for i := 0; i < fieldCount; i++ {
			if off+4 > len(payload) {
				ok = false
				break
			}
			ie := int(binary.BigEndian.Uint16(payload[off : off+2]))
			length := int(binary.BigEndian.Uint16(payload[off+2 : off+4]))
			off += 4
			if enterpriseCapable && ie&0x8000 != 0 {
				// IE enterprise: si salta l'enterprise number e si rende l'id
				// negativo, così non corrisponde mai a un IE noto.
				ie &= 0x7FFF
				off += 4
				ie = -ie
			}
			fields = append(fields, templateField{ie: ie, length: length})
		}
		if ok && len(fields) > 0 {
			out = append(out, d.storeTemplate(templateKey{exporterIP, odid, tid}, fields)...)
		}
	}
	return out
}

// storeTemplate registra un template (sostituendo un eventuale precedente) e
// ritenta i data set rimasti in attesa per quella chiave.
func (d *Decoder) storeTemplate(key templateKey, fields []templateField) []FlowRecord {
	d.mu.Lock()
	d.templates[key] = templateEntry{fields: fields, created: d.now()}
	d.evictLocked()
	waiting := d.pending[key]
	delete(d.pending, key)
	d.pendingN -= len(waiting)
	d.mu.Unlock()

	var out []FlowRecord
	for _, p := range waiting {
		out = append(out, decodeDataSet(p.payload, fields, p.exporterIP, p.exportTS)...)
	}
	return out
}

// evictLocked mantiene la cache entro MaxTemplates: prima i template scaduti,
// poi il più vecchio. Va chiamata con il lock già preso.
func (d *Decoder) evictLocked() {
	if len(d.templates) <= MaxTemplates {
		return
	}
	now := d.now()
	for k, e := range d.templates {
		if now.Sub(e.created) > TemplateTTL {
			delete(d.templates, k)
		}
	}
	for len(d.templates) > MaxTemplates {
		var oldestKey templateKey
		var oldest time.Time
		first := true
		for k, e := range d.templates {
			if first || e.created.Before(oldest) {
				oldestKey, oldest, first = k, e.created, false
			}
		}
		delete(d.templates, oldestKey)
	}
}

// template ritorna i campi di un template valido, scartandolo se scaduto.
func (d *Decoder) template(key templateKey) []templateField {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.templates[key]
	if !ok {
		return nil
	}
	if d.now().Sub(e.created) > TemplateTTL {
		delete(d.templates, key)
		return nil
	}
	return e.fields
}

// bufferPending mette da parte un data set arrivato prima del suo template.
func (d *Decoder) bufferPending(key templateKey, payload []byte, exporterIP string,
	exportTS int64, stats *ParseStats) {

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pendingN >= MaxPendingSets {
		stats.DataBeforeTemplateDropped++
		return
	}
	// Copia: payload punta al buffer di ricezione, che verrà riusato.
	buf := make([]byte, len(payload))
	copy(buf, payload)
	d.pending[key] = append(d.pending[key], pendingSet{buf, exporterIP, exportTS})
	d.pendingN++
}

// --- decodifica dei data record ---

func decodeDataSet(payload []byte, fields []templateField, exporterIP string, exportTS int64) []FlowRecord {
	recLen, hasVar := 0, false
	for _, f := range fields {
		if f.length == varLengthMarker {
			hasVar = true
			continue
		}
		recLen += f.length
	}

	var out []FlowRecord
	off := 0
	for {
		var rec map[int][]byte
		if hasVar {
			var next int
			rec, next = decodeVarRecord(payload, off, fields)
			if rec == nil {
				break
			}
			off = next
		} else {
			if recLen == 0 || off+recLen > len(payload) {
				break
			}
			rec = make(map[int][]byte, len(fields))
			pos := off
			for _, f := range fields {
				rec[f.ie] = payload[pos : pos+f.length]
				pos += f.length
			}
			off += recLen
		}
		if r, ok := normalizeFlow(rec, exporterIP, exportTS); ok {
			out = append(out, r)
		}
	}
	return out
}

// decodeVarRecord decodifica un record con campi a lunghezza variabile
// (RFC 7011 §7). Ritorna nil quando il payload è esaurito o troncato.
func decodeVarRecord(payload []byte, off int, fields []templateField) (map[int][]byte, int) {
	rec := make(map[int][]byte, len(fields))
	pos := off
	for _, f := range fields {
		length := f.length
		if length == varLengthMarker {
			if pos >= len(payload) {
				return nil, off
			}
			length = int(payload[pos])
			pos++
			if length == 255 {
				if pos+2 > len(payload) {
					return nil, off
				}
				length = int(binary.BigEndian.Uint16(payload[pos : pos+2]))
				pos += 2
			}
		}
		if length < 0 || pos+length > len(payload) {
			return nil, off
		}
		rec[f.ie] = payload[pos : pos+length]
		pos += length
	}
	return rec, pos
}

func beUint(b []byte) int64 {
	var v int64
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v
}

// normalizeFlow trasforma i campi grezzi in un record. Senza IP sorgente e
// destinazione il record non è utilizzabile e viene scartato.
func normalizeFlow(rec map[int][]byte, exporterIP string, exportTS int64) (FlowRecord, bool) {
	var zero FlowRecord

	src, okSrc := addrFrom(rec, ieSrc4, ieSrc6)
	dst, okDst := addrFrom(rec, ieDst4, ieDst6)
	if !okSrc || !okDst {
		return zero, false
	}

	endTS := exportTS
	if b, ok := rec[ieEndSec]; ok {
		endTS = beUint(b)
	} else if b, ok := rec[ieEndMsec]; ok {
		endTS = beUint(b) / 1000
	}

	// Il Python emette None per protocollo e porta pari a 0: qui -1.
	proto, dport := -1, -1
	if v := beUint(rec[ieProto]); v != 0 {
		proto = int(v)
	}
	if v := beUint(rec[ieDstPort]); v != 0 {
		dport = int(v)
	}
	return FlowRecord{
		SrcIP: src, DstIP: dst, Protocol: proto, DstPort: dport,
		Bytes: beUint(rec[ieBytes]), Packets: beUint(rec[iePackets]),
		FlowEndTS: endTS, ExporterIP: exporterIP,
	}, true
}

func addrFrom(rec map[int][]byte, ie4, ie6 int) (string, bool) {
	if b, ok := rec[ie4]; ok && len(b) == 4 {
		a, _ := netip.AddrFromSlice(b)
		return a.String(), true
	}
	if b, ok := rec[ie6]; ok && len(b) == 16 {
		a, _ := netip.AddrFromSlice(b)
		return a.String(), true
	}
	return "", false
}
