package ingest

import (
	"encoding/binary"
	"net/netip"
)

// FlowRecord è un flusso normalizzato, formato comune a sFlow e NetFlow/IPFIX.
type FlowRecord struct {
	SrcIP      string
	DstIP      string
	Protocol   int
	DstPort    int // -1 = non applicabile (protocollo senza porte)
	Bytes      int64
	Packets    int64
	FlowEndTS  int64
	ExporterIP string
}

const (
	sfFlowSample         = 1
	sfCounterSample      = 2
	sfFlowSampleExp      = 3
	sfCounterSampleExp   = 4
	sfRecRawPacketHeader = 1

	sfMaxSamples = 64 // cap per datagramma, come nel Python
	sfMaxRecords = 16 // cap per sample
)

// ParseSFlow decodifica un datagramma sFlow v5 in record di flusso.
//
// SEMANTICA DI STIMA (vincolante): sFlow campiona 1 pacchetto ogni
// sampling_rate, quindi i valori emessi sono STIME dell'intero traffico:
//
//	bytes   = frame_length * sampling_rate
//	packets = sampling_rate
//
// I counter sample non sono usati: header letto, corpo saltato, con metrica
// counter_samples_skipped.
//
// Ritorna anche il numero di counter sample saltati, che il chiamante conta
// come metrica (il decoder resta una funzione pura, senza dipendenze).
func ParseSFlow(data []byte, exporterIP string, now int64) (records []FlowRecord, countersSkipped int, ok bool) {
	// Header minimo + versione 5.
	if len(data) < 28 || binary.BigEndian.Uint32(data[0:4]) != 5 {
		return nil, 0, false
	}
	addrType := binary.BigEndian.Uint32(data[4:8])
	off := 8
	if addrType == 1 {
		off += 4 // IPv4
	} else {
		off += 16 // IPv6
	}
	off += 12 // sub-agent id, sequence, uptime
	if off+4 > len(data) {
		return nil, 0, false
	}
	numSamples := int(binary.BigEndian.Uint32(data[off : off+4]))
	off += 4
	if numSamples > sfMaxSamples {
		numSamples = sfMaxSamples
	}

	for i := 0; i < numSamples; i++ {
		if off+8 > len(data) {
			break
		}
		sampleType := binary.BigEndian.Uint32(data[off : off+4])
		sampleLen := int(binary.BigEndian.Uint32(data[off+4 : off+8]))
		off += 8
		if sampleLen < 0 || off+sampleLen > len(data) {
			break
		}
		payload := data[off : off+sampleLen]
		off += sampleLen

		switch sampleType & 0xFFF {
		case sfFlowSample:
			records = append(records, sflowFlowSample(payload, exporterIP, now)...)
		case sfCounterSample, sfCounterSampleExp:
			countersSkipped++
		case sfFlowSampleExp:
			// Layout diverso, non supportato: si salta come nel Python.
		}
	}
	return records, countersSkipped, true
}

func sflowFlowSample(p []byte, exporterIP string, now int64) []FlowRecord {
	if len(p) < 32 {
		return nil
	}
	samplingRate := int64(binary.BigEndian.Uint32(p[8:12]))
	if samplingRate == 0 {
		samplingRate = 1
	}
	numRecords := int(binary.BigEndian.Uint32(p[28:32]))
	if numRecords > sfMaxRecords {
		numRecords = sfMaxRecords
	}

	var out []FlowRecord
	off := 32
	for i := 0; i < numRecords; i++ {
		if off+8 > len(p) {
			break
		}
		recType := binary.BigEndian.Uint32(p[off : off+4])
		recLen := int(binary.BigEndian.Uint32(p[off+4 : off+8]))
		off += 8
		if recLen < 0 || off+recLen > len(p) {
			break
		}
		body := p[off : off+recLen]
		off += recLen

		if recType&0xFFF == sfRecRawPacketHeader {
			if rec, ok := sflowRawHeader(body, samplingRate, exporterIP, now); ok {
				out = append(out, rec)
			}
		}
	}
	return out
}

// sflowRawHeader estrae il flusso dall'intestazione del pacchetto campionato
// (solo Ethernet + IPv4, come il Python).
func sflowRawHeader(body []byte, samplingRate int64, exporterIP string, now int64) (FlowRecord, bool) {
	var zero FlowRecord
	if len(body) < 16 {
		return zero, false
	}
	protoHdr := binary.BigEndian.Uint32(body[0:4])
	frameLen := int64(binary.BigEndian.Uint32(body[4:8]))
	hdrLen := int(binary.BigEndian.Uint32(body[12:16]))
	if protoHdr != 1 { // solo Ethernet
		return zero, false
	}
	end := 16 + hdrLen
	if hdrLen < 0 || end > len(body) {
		end = len(body)
	}
	frame := body[16:end]
	if len(frame) < 14 {
		return zero, false
	}

	ethertype := binary.BigEndian.Uint16(frame[12:14])
	off := 14
	if ethertype == 0x8100 && len(frame) >= 18 { // 802.1Q
		ethertype = binary.BigEndian.Uint16(frame[16:18])
		off = 18
	}
	if ethertype != 0x0800 || len(frame) < off+20 { // solo IPv4
		return zero, false
	}
	ihl := int(frame[off]&0x0F) * 4
	proto := int(frame[off+9])
	src, _ := netip.AddrFromSlice(frame[off+12 : off+16])
	dst, _ := netip.AddrFromSlice(frame[off+16 : off+20])

	dstPort := -1
	if l4 := off + ihl; (proto == 6 || proto == 17) && len(frame) >= l4+4 {
		dstPort = int(binary.BigEndian.Uint16(frame[l4+2 : l4+4]))
	}
	return FlowRecord{
		SrcIP: src.String(), DstIP: dst.String(), Protocol: proto, DstPort: dstPort,
		// Stima: un campione rappresenta samplingRate pacchetti reali.
		Bytes: frameLen * samplingRate, Packets: samplingRate,
		FlowEndTS: now, ExporterIP: exporterIP,
	}, true
}
