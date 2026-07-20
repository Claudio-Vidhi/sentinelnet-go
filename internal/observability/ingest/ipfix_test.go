package ingest

import (
	"encoding/binary"
	"testing"
	"time"
)

// --- costruttori di datagrammi ---

func ipfixHeader(length int, exportTime, odid uint32) []byte {
	h := make([]byte, 16)
	binary.BigEndian.PutUint16(h[0:2], 10)
	binary.BigEndian.PutUint16(h[2:4], uint16(length))
	binary.BigEndian.PutUint32(h[4:8], exportTime)
	binary.BigEndian.PutUint32(h[12:16], odid)
	return h
}

// templateSet costruisce un set template IPFIX (id 2) per un template id dato.
func templateSet(tid uint16, fields [][2]uint16) []byte {
	body := make([]byte, 0, 4+len(fields)*4)
	body = append(body, be16(tid)...)
	body = append(body, be16(uint16(len(fields)))...)
	for _, f := range fields {
		body = append(body, be16(f[0])...)
		body = append(body, be16(f[1])...)
	}
	set := append(be16(2), be16(uint16(4+len(body)))...)
	return append(set, body...)
}

func dataSet(tid uint16, records ...[]byte) []byte {
	body := []byte{}
	for _, r := range records {
		body = append(body, r...)
	}
	set := append(be16(tid), be16(uint16(4+len(body)))...)
	return append(set, body...)
}

// standardFields: src4, dst4, proto, dstport, bytes, packets.
var standardFields = [][2]uint16{
	{ieSrc4, 4}, {ieDst4, 4}, {ieProto, 1}, {ieDstPort, 2}, {ieBytes, 4}, {iePackets, 4},
}

func standardRecord(src, dst [4]byte, proto uint8, dport uint16, nbytes, npkts uint32) []byte {
	r := make([]byte, 0, 19)
	r = append(r, src[:]...)
	r = append(r, dst[:]...)
	r = append(r, proto)
	r = append(r, be16(dport)...)
	r = append(r, be32(nbytes)...)
	r = append(r, be32(npkts)...)
	return r
}

func ipfixDatagram(exportTime, odid uint32, sets ...[]byte) []byte {
	body := []byte{}
	for _, s := range sets {
		body = append(body, s...)
	}
	return append(ipfixHeader(16+len(body), exportTime, odid), body...)
}

// --- test ---

func TestIPFIXTemplateThenData(t *testing.T) {
	d := NewDecoder()
	rec := standardRecord([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 443, 1500, 10)
	dg := ipfixDatagram(1_800_000_000, 1, templateSet(256, standardFields), dataSet(256, rec))

	recs, stats := d.Parse(dg, "10.0.0.9")
	if stats.ParseErrors != 0 {
		t.Errorf("parse errors = %d", stats.ParseErrors)
	}
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1", len(recs))
	}
	r := recs[0]
	if r.SrcIP != "10.0.0.1" || r.DstIP != "10.0.0.2" {
		t.Errorf("IP = %s -> %s", r.SrcIP, r.DstIP)
	}
	if r.Protocol != 6 || r.DstPort != 443 || r.Bytes != 1500 || r.Packets != 10 {
		t.Errorf("record = %+v", r)
	}
	if r.FlowEndTS != 1_800_000_000 {
		t.Errorf("flow_end_ts = %d, atteso l'export time", r.FlowEndTS)
	}
	if d.TemplateCacheSize() != 1 {
		t.Errorf("template in cache = %d, atteso 1", d.TemplateCacheSize())
	}
}

// Il caso che rende necessario il buffer: i dati arrivano prima del template.
// Devono essere ri-decodificati quando il template arriva, non persi.
func TestIPFIXDataBeforeTemplateIsReplayed(t *testing.T) {
	d := NewDecoder()
	rec := standardRecord([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 443, 1500, 10)

	// 1) Solo dati: nessun record, il set resta in attesa.
	recs, stats := d.Parse(ipfixDatagram(1_800_000_000, 1, dataSet(256, rec)), "10.0.0.9")
	if len(recs) != 0 {
		t.Fatalf("record = %d, attesi 0 senza template", len(recs))
	}
	if stats.DataBeforeTemplateDropped != 0 {
		t.Errorf("scartati = %d, attesi 0 (il buffer non è pieno)", stats.DataBeforeTemplateDropped)
	}

	// 2) Arriva il template: il set in attesa viene decodificato.
	recs, _ = d.Parse(ipfixDatagram(1_800_000_000, 1, templateSet(256, standardFields)), "10.0.0.9")
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1 dopo l'arrivo del template", len(recs))
	}
	if recs[0].SrcIP != "10.0.0.1" || recs[0].Bytes != 1500 {
		t.Errorf("record ricostruito errato: %+v", recs[0])
	}
}

// Il buffer è limitato: oltre MaxPendingSets si scarta contando la metrica,
// altrimenti un exporter che non manda mai template farebbe crescere la memoria.
func TestIPFIXPendingBufferIsBounded(t *testing.T) {
	d := NewDecoder()
	rec := standardRecord([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 443, 1500, 10)

	total := 0
	for i := 0; i < MaxPendingSets+10; i++ {
		// Template id diverso ogni volta: nessuno verrà mai risolto.
		_, stats := d.Parse(ipfixDatagram(1, 1, dataSet(uint16(300+i), rec)), "10.0.0.9")
		total += stats.DataBeforeTemplateDropped
	}
	if total != 10 {
		t.Errorf("set scartati = %d, attesi 10", total)
	}
}

// Un template ri-annunciato sostituisce il precedente.
func TestIPFIXTemplateReannouncementReplaces(t *testing.T) {
	d := NewDecoder()
	// Primo template: solo src/dst.
	shortFields := [][2]uint16{{ieSrc4, 4}, {ieDst4, 4}}
	shortRec := append([]byte{10, 0, 0, 1}, 10, 0, 0, 2)
	d.Parse(ipfixDatagram(1, 1, templateSet(256, shortFields)), "10.0.0.9")
	recs, _ := d.Parse(ipfixDatagram(1, 1, dataSet(256, shortRec)), "10.0.0.9")
	if len(recs) != 1 || recs[0].Protocol != -1 {
		t.Fatalf("primo template: %+v", recs)
	}

	// Ri-annuncio con più campi.
	d.Parse(ipfixDatagram(1, 1, templateSet(256, standardFields)), "10.0.0.9")
	full := standardRecord([4]byte{10, 0, 0, 3}, [4]byte{10, 0, 0, 4}, 17, 53, 99, 1)
	recs, _ = d.Parse(ipfixDatagram(1, 1, dataSet(256, full)), "10.0.0.9")
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1", len(recs))
	}
	if recs[0].Protocol != 17 || recs[0].DstPort != 53 {
		t.Errorf("il template ri-annunciato non ha sostituito il precedente: %+v", recs[0])
	}
	if d.TemplateCacheSize() != 1 {
		t.Errorf("template in cache = %d, atteso 1", d.TemplateCacheSize())
	}
}

// I template scadono: dopo il TTL i dati tornano in attesa.
func TestIPFIXTemplateExpires(t *testing.T) {
	d := NewDecoder()
	now := time.Unix(1_800_000_000, 0)
	d.now = func() time.Time { return now }

	rec := standardRecord([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 443, 1500, 10)
	d.Parse(ipfixDatagram(1, 1, templateSet(256, standardFields)), "10.0.0.9")
	if recs, _ := d.Parse(ipfixDatagram(1, 1, dataSet(256, rec)), "10.0.0.9"); len(recs) != 1 {
		t.Fatalf("prima della scadenza: record = %d, atteso 1", len(recs))
	}

	now = now.Add(TemplateTTL + time.Second)
	recs, _ := d.Parse(ipfixDatagram(1, 1, dataSet(256, rec)), "10.0.0.9")
	if len(recs) != 0 {
		t.Errorf("dopo la scadenza: record = %d, attesi 0", len(recs))
	}
	if d.TemplateCacheSize() != 0 {
		t.Errorf("il template scaduto non è stato rimosso: cache = %d", d.TemplateCacheSize())
	}
}

// Lo stesso template id di exporter diversi non deve collidere.
func TestIPFIXTemplatesAreScopedByExporterAndDomain(t *testing.T) {
	d := NewDecoder()
	rec := standardRecord([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 443, 1500, 10)

	d.Parse(ipfixDatagram(1, 1, templateSet(256, standardFields)), "10.0.0.9")

	// Stesso template id, exporter diverso: non deve risolversi.
	if recs, _ := d.Parse(ipfixDatagram(1, 1, dataSet(256, rec)), "10.0.0.8"); len(recs) != 0 {
		t.Errorf("exporter diverso: record = %d, attesi 0", len(recs))
	}
	// Stesso exporter, observation domain diverso: non deve risolversi.
	if recs, _ := d.Parse(ipfixDatagram(1, 2, dataSet(256, rec)), "10.0.0.9"); len(recs) != 0 {
		t.Errorf("domain diverso: record = %d, attesi 0", len(recs))
	}
	// Chiave completa corretta: si risolve.
	if recs, _ := d.Parse(ipfixDatagram(1, 1, dataSet(256, rec)), "10.0.0.9"); len(recs) != 1 {
		t.Errorf("chiave corretta: record = %d, atteso 1", len(recs))
	}
}

// Gli IE enterprise portano 4 byte extra da saltare: se non li si salta, tutti
// i campi successivi risultano disallineati.
func TestIPFIXEnterpriseFieldsAreSkipped(t *testing.T) {
	d := NewDecoder()
	body := append(be16(256), be16(3)...)
	body = append(body, be16(ieSrc4)...)
	body = append(body, be16(4)...)
	body = append(body, be16(0x8000|99)...) // IE enterprise
	body = append(body, be16(2)...)         // lunghezza 2
	body = append(body, be32(12345)...)     // enterprise number, da saltare
	body = append(body, be16(ieDst4)...)
	body = append(body, be16(4)...)
	tset := append(be16(2), be16(uint16(4+len(body)))...)
	tset = append(tset, body...)

	rec := []byte{10, 0, 0, 1, 0xAA, 0xBB, 10, 0, 0, 2}
	recs, _ := d.Parse(ipfixDatagram(1, 1, tset, dataSet(256, rec)), "10.0.0.9")
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1", len(recs))
	}
	if recs[0].SrcIP != "10.0.0.1" || recs[0].DstIP != "10.0.0.2" {
		t.Errorf("campi disallineati: %+v — l'enterprise number non è stato saltato", recs[0])
	}
}

func TestNetFlowV5(t *testing.T) {
	d := NewDecoder()
	dg := make([]byte, 24+48)
	binary.BigEndian.PutUint16(dg[0:2], 5)
	binary.BigEndian.PutUint16(dg[2:4], 1)              // count
	binary.BigEndian.PutUint32(dg[8:12], 1_800_000_000) // unix_secs
	r := dg[24:]
	copy(r[0:4], []byte{10, 0, 0, 1})
	copy(r[4:8], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint32(r[16:20], 10)   // dPkts
	binary.BigEndian.PutUint32(r[20:24], 1500) // dOctets
	binary.BigEndian.PutUint16(r[34:36], 443)  // dstport
	r[38] = 6                                  // protocollo

	recs, stats := d.Parse(dg, "10.0.0.9")
	if stats.ParseErrors != 0 {
		t.Errorf("parse errors = %d", stats.ParseErrors)
	}
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1", len(recs))
	}
	got := recs[0]
	if got.SrcIP != "10.0.0.1" || got.DstIP != "10.0.0.2" || got.Protocol != 6 ||
		got.DstPort != 443 || got.Bytes != 1500 || got.Packets != 10 ||
		got.FlowEndTS != 1_800_000_000 {
		t.Errorf("record = %+v", got)
	}
}

func TestParseUnknownVersionCountsError(t *testing.T) {
	d := NewDecoder()
	_, stats := d.Parse([]byte{0, 99, 0, 0}, "10.0.0.9")
	if stats.ParseErrors != 1 {
		t.Errorf("parse errors = %d, atteso 1", stats.ParseErrors)
	}
}

// Come per sFlow: nessun troncamento deve provocare un panic.
func TestIPFIXNeverPanicsOnTruncation(t *testing.T) {
	rec := standardRecord([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, 6, 443, 1500, 10)
	dg := ipfixDatagram(1_800_000_000, 1, templateSet(256, standardFields), dataSet(256, rec))
	for i := 0; i <= len(dg); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic con datagramma troncato a %d byte: %v", i, r)
				}
			}()
			NewDecoder().Parse(dg[:i], "10.0.0.9")
		}()
	}
}

// I campi a lunghezza variabile (RFC 7011 §7) non devono sballare il record.
func TestIPFIXVariableLengthFields(t *testing.T) {
	d := NewDecoder()
	fields := [][2]uint16{{ieSrc4, 4}, {ieDst4, 4}, {200, varLengthMarker}, {ieProto, 1}}
	rec := []byte{10, 0, 0, 1, 10, 0, 0, 2, 3, 'a', 'b', 'c', 6}

	recs, _ := d.Parse(ipfixDatagram(1, 1, templateSet(256, fields), dataSet(256, rec)), "10.0.0.9")
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1", len(recs))
	}
	if recs[0].SrcIP != "10.0.0.1" || recs[0].Protocol != 6 {
		t.Errorf("campo a lunghezza variabile mal gestito: %+v", recs[0])
	}
}
