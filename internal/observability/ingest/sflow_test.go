package ingest

import (
	"encoding/binary"
	"testing"
)

func be32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func be16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// ipv4Frame costruisce un frame Ethernet+IPv4+TCP minimale.
func ipv4Frame(srcPort, dstPort uint16) []byte {
	f := make([]byte, 0, 54)
	f = append(f, make([]byte, 12)...) // MAC dst + src
	f = append(f, be16(0x0800)...)     // ethertype IPv4
	ip := make([]byte, 20)
	ip[0] = 0x45 // versione 4, IHL 5 (20 byte)
	ip[9] = 6    // TCP
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	f = append(f, ip...)
	f = append(f, be16(srcPort)...)
	f = append(f, be16(dstPort)...)
	return f
}

// sflowDatagram costruisce un datagramma v5 con un flow sample contenente un
// raw packet header.
func sflowDatagram(samplingRate, frameLen uint32, frame []byte) []byte {
	raw := make([]byte, 0, 16+len(frame))
	raw = append(raw, be32(1)...)                  // protocollo header = Ethernet
	raw = append(raw, be32(frameLen)...)           // frame length originale
	raw = append(raw, be32(0)...)                  // stripped
	raw = append(raw, be32(uint32(len(frame)))...) // header length
	raw = append(raw, frame...)

	rec := append(be32(sfRecRawPacketHeader), be32(uint32(len(raw)))...)
	rec = append(rec, raw...)

	sample := make([]byte, 32)
	binary.BigEndian.PutUint32(sample[8:12], samplingRate)
	binary.BigEndian.PutUint32(sample[28:32], 1) // un record
	sample = append(sample, rec...)

	dg := make([]byte, 0, 64)
	dg = append(dg, be32(5)...) // versione 5
	dg = append(dg, be32(1)...) // agent address type = IPv4
	dg = append(dg, make([]byte, 4)...)
	dg = append(dg, make([]byte, 12)...) // sub-agent, sequence, uptime
	dg = append(dg, be32(1)...)          // un sample
	dg = append(dg, be32(sfFlowSample)...)
	dg = append(dg, be32(uint32(len(sample)))...)
	dg = append(dg, sample...)
	return dg
}

func TestParseSFlowEstimatesFromSamplingRate(t *testing.T) {
	const rate, frameLen = 1000, 1500
	recs, skipped, ok := ParseSFlow(sflowDatagram(rate, frameLen, ipv4Frame(12345, 443)), "10.0.0.9", 1_800_000_000)
	if !ok {
		t.Fatal("decodifica fallita su datagramma valido")
	}
	if skipped != 0 {
		t.Errorf("counter saltati = %d, attesi 0", skipped)
	}
	if len(recs) != 1 {
		t.Fatalf("record = %d, atteso 1", len(recs))
	}
	r := recs[0]
	if r.SrcIP != "10.0.0.1" || r.DstIP != "10.0.0.2" {
		t.Errorf("IP = %s -> %s, attesi 10.0.0.1 -> 10.0.0.2", r.SrcIP, r.DstIP)
	}
	if r.Protocol != 6 || r.DstPort != 443 {
		t.Errorf("protocollo/porta = %d/%d, attesi 6/443", r.Protocol, r.DstPort)
	}
	// La stima è vincolante: bytes = frame_length * sampling_rate.
	if r.Bytes != frameLen*rate {
		t.Errorf("bytes = %d, attesi %d (frame_length * sampling_rate)", r.Bytes, frameLen*rate)
	}
	if r.Packets != rate {
		t.Errorf("packets = %d, attesi %d (sampling_rate)", r.Packets, rate)
	}
	if r.ExporterIP != "10.0.0.9" {
		t.Errorf("exporter = %q", r.ExporterIP)
	}
}

// sampling_rate 0 non deve azzerare la stima: si usa 1.
func TestParseSFlowZeroSamplingRate(t *testing.T) {
	recs, _, ok := ParseSFlow(sflowDatagram(0, 1500, ipv4Frame(1, 80)), "10.0.0.9", 0)
	if !ok || len(recs) != 1 {
		t.Fatalf("ok=%v record=%d", ok, len(recs))
	}
	if recs[0].Packets != 1 || recs[0].Bytes != 1500 {
		t.Errorf("packets=%d bytes=%d, attesi 1/1500", recs[0].Packets, recs[0].Bytes)
	}
}

func TestParseSFlowVLANTaggedFrame(t *testing.T) {
	f := make([]byte, 0, 58)
	f = append(f, make([]byte, 12)...)
	f = append(f, be16(0x8100)...) // tag 802.1Q
	f = append(f, be16(10)...)     // VLAN 10
	f = append(f, be16(0x0800)...) // ethertype interno IPv4
	ip := make([]byte, 20)
	ip[0], ip[9] = 0x45, 17 // UDP
	copy(ip[12:16], []byte{192, 168, 1, 1})
	copy(ip[16:20], []byte{192, 168, 1, 2})
	f = append(f, ip...)
	f = append(f, be16(5353)...)
	f = append(f, be16(53)...)

	recs, _, ok := ParseSFlow(sflowDatagram(100, 200, f), "10.0.0.9", 0)
	if !ok || len(recs) != 1 {
		t.Fatalf("frame con tag VLAN non decodificato: ok=%v record=%d", ok, len(recs))
	}
	if recs[0].SrcIP != "192.168.1.1" || recs[0].Protocol != 17 || recs[0].DstPort != 53 {
		t.Errorf("record = %+v", recs[0])
	}
}

func TestParseSFlowRejectsWrongVersion(t *testing.T) {
	dg := sflowDatagram(10, 100, ipv4Frame(1, 2))
	binary.BigEndian.PutUint32(dg[0:4], 4) // v4, non supportata
	if _, _, ok := ParseSFlow(dg, "10.0.0.9", 0); ok {
		t.Error("una versione diversa da 5 doveva essere rifiutata")
	}
}

func TestParseSFlowCountsSkippedCounterSamples(t *testing.T) {
	dg := make([]byte, 0, 48)
	dg = append(dg, be32(5)...)
	dg = append(dg, be32(1)...)
	dg = append(dg, make([]byte, 4)...)
	dg = append(dg, make([]byte, 12)...)
	dg = append(dg, be32(1)...) // un sample
	dg = append(dg, be32(sfCounterSample)...)
	dg = append(dg, be32(8)...)
	dg = append(dg, make([]byte, 8)...)

	recs, skipped, ok := ParseSFlow(dg, "10.0.0.9", 0)
	if !ok {
		t.Fatal("decodifica fallita")
	}
	if len(recs) != 0 {
		t.Errorf("record = %d, attesi 0: i counter sample non producono flussi", len(recs))
	}
	if skipped != 1 {
		t.Errorf("counter saltati = %d, atteso 1", skipped)
	}
}

// Il caso che in Go conta più che in Python: ogni troncamento di un
// datagramma valido deve terminare senza panic. Il Python tollera gli slice
// corti, encoding/binary no.
func TestParseSFlowNeverPanicsOnTruncation(t *testing.T) {
	dg := sflowDatagram(1000, 1500, ipv4Frame(12345, 443))
	for i := 0; i <= len(dg); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic con datagramma troncato a %d byte: %v", i, r)
				}
			}()
			ParseSFlow(dg[:i], "10.0.0.9", 0)
		}()
	}
}

// Lunghezze dichiarate assurde non devono provocare letture fuori dai limiti.
func TestParseSFlowNeverPanicsOnBogusLengths(t *testing.T) {
	cases := [][]byte{
		nil, {}, make([]byte, 27),
	}
	// Sample length enorme rispetto al datagramma.
	dg := sflowDatagram(1000, 1500, ipv4Frame(1, 2))
	bogus := append([]byte(nil), dg...)
	binary.BigEndian.PutUint32(bogus[28:32], 0xFFFFFFF0)
	cases = append(cases, bogus)
	// Numero di sample enorme.
	bogus2 := append([]byte(nil), dg...)
	binary.BigEndian.PutUint32(bogus2[24:28], 0xFFFFFFFF)
	cases = append(cases, bogus2)

	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic sul caso %d: %v", i, r)
				}
			}()
			ParseSFlow(in, "10.0.0.9", 0)
		}()
	}
}
