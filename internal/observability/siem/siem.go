// Package siem: modelli, parser e aggregatori per il registro Flow SIEM.
// Porta di routers/flow_siem.py e observability/fieldmap.py.
package siem

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	reFgtKV = regexp.MustCompile(`(\w+)=(?:"([^"]*)"|(\S+))`)
	reIP    = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

var SecurityActions = map[string]bool{
	"deny":        true,
	"drop":        true,
	"blocked":     true,
	"block":       true,
	"reject":      true,
	"reset-both":  true,
	"reset-server": true,
	"reset-client": true,
	"close":       false,
	"accept":      false,
	"allow":       false,
	"permitted":   false,
	"permit":      false,
	"server-rst":  true,
	"client-rst":  true,
}

var ProtoNum = map[string]string{
	"1":   "ICMP",
	"6":   "TCP",
	"17":  "UDP",
	"47":  "GRE",
	"50":  "ESP",
	"51":  "AH",
	"58":  "ICMPv6",
	"89":  "OSPF",
	"112": "VRRP",
}

type Event struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	TS         int64  `json:"ts"`
	Tenant     string `json:"tenant"`
	DeviceIP   string `json:"device_ip"`
	Severity   *int   `json:"severity"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	SrcPort    *int   `json:"src_port"`
	DstPort    *int   `json:"dst_port"`
	Proto      string `json:"proto"`
	Bytes      *int64 `json:"bytes"`
	Action     string `json:"action"`
	IsDeny     bool   `json:"is_deny"`
	ThreatFlag string `json:"threat_flag"`
	Message    string `json:"message"`
}

type HistogramBucket struct {
	BucketIndex int    `json:"bucket_index"`
	Timestamp   string `json:"timestamp"`
	Count       int    `json:"count"`
	DenyCount   int    `json:"deny_count"`
}

type FacetItem struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

type FacetsResponse struct {
	TopSrcIPs        []FacetItem `json:"top_src_ips"`
	TopDstIPs        []FacetItem `json:"top_dst_ips"`
	ThreatFlags       []FacetItem `json:"threat_flags"`
	Actions           []FacetItem `json:"actions"`
	EventsConsidered int         `json:"events_considered"`
}

func ExtractKV(message string) map[string]string {
	kv := map[string]string{}
	for _, m := range reFgtKV.FindAllStringSubmatch(message, -1) {
		val := m[2]
		if val == "" {
			val = m[3]
		}
		kv[m[1]] = val
	}
	return kv
}

func ExtractEndpoints(message string, kv map[string]string) (src, dst string) {
	src = kv["srcip"]
	if src == "" {
		src = kv["src"]
	}
	dst = kv["dstip"]
	if dst == "" {
		dst = kv["dst"]
	}

	if src == "" || dst == "" {
		matches := reIP.FindAllString(message, 2)
		if len(matches) > 0 && src == "" {
			src = matches[0]
		}
		if len(matches) > 1 && dst == "" {
			dst = matches[1]
		}
	}
	return src, dst
}

func IsDeny(action string) bool {
	norm := strings.ToLower(strings.TrimSpace(action))
	return SecurityActions[norm]
}

func ThreatFlag(dstIP string, isDeny bool, severity *int, nbytes *int64) string {
	if isDeny {
		return "BLOCKED_TRAFFIC"
	}
	if severity != nil && *severity <= 3 {
		return "HIGH_SEVERITY"
	}
	if nbytes != nil && *nbytes > 1_000_000 {
		return "HIGH_VOLUME_TRANSFER"
	}
	if dstIP == "8.8.8.8" || dstIP == "1.1.1.1" {
		return "EXTERNAL_DNS"
	}
	return "NORMAL"
}

func ToEvent(id int64, ts int64, tenant, deviceIP string, severity *int, actionRaw, message string) Event {
	kv := ExtractKV(message)
	src, dst := ExtractEndpoints(message, kv)

	action := actionRaw
	if action == "" {
		action = kv["action"]
		if action == "" {
			action = kv["utmaction"]
		}
	}
	deny := IsDeny(action)

	var sent, rcvd int64
	if s := kv["sentbyte"]; s != "" {
		sent, _ = strconv.ParseInt(s, 10, 64)
	}
	if r := kv["rcvdbyte"]; r != "" {
		rcvd, _ = strconv.ParseInt(r, 10, 64)
	}
	var nbytes *int64
	if sent+rcvd > 0 {
		tot := sent + rcvd
		nbytes = &tot
	}

	proto := kv["proto"]
	if proto == "" {
		proto = kv["service"]
	}
	if name, ok := ProtoNum[proto]; ok {
		proto = name
	} else if proto != "" {
		proto = strings.ToUpper(proto)
	}

	var srcPort, dstPort *int
	if sp := kv["srcport"]; sp != "" {
		if p, err := strconv.Atoi(sp); err == nil {
			srcPort = &p
		}
	}
	if dp := kv["dstport"]; dp != "" {
		if p, err := strconv.Atoi(dp); err == nil {
			dstPort = &p
		}
	}

	tStr := time.Unix(ts, 0).UTC().Format(time.RFC3339)

	return Event{
		ID:         id,
		Timestamp:  tStr,
		TS:         ts,
		Tenant:     tenant,
		DeviceIP:   deviceIP,
		Severity:   severity,
		SrcIP:      src,
		DstIP:      dst,
		SrcPort:    srcPort,
		DstPort:    dstPort,
		Proto:      proto,
		Bytes:      nbytes,
		Action:     strings.ToUpper(action),
		IsDeny:     deny,
		ThreatFlag: ThreatFlag(dst, deny, severity, nbytes),
		Message:    message,
	}
}

func WindowToSeconds(window string) int {
	w := strings.ToLower(strings.TrimSpace(window))
	if strings.HasSuffix(w, "m") {
		n, _ := strconv.Atoi(strings.TrimSuffix(w, "m"))
		if n > 0 {
			return max(60, n*60)
		}
	}
	if strings.HasSuffix(w, "h") {
		n, _ := strconv.Atoi(strings.TrimSuffix(w, "h"))
		if n > 0 {
			return max(60, n*3600)
		}
	}
	if strings.HasSuffix(w, "d") {
		n, _ := strconv.Atoi(strings.TrimSuffix(w, "d"))
		if n > 0 {
			return max(60, n*86400)
		}
	}
	return 86400
}

func ParseFieldQuery(q string) (field, value string) {
	if !strings.Contains(q, ":") {
		return "", ""
	}
	parts := strings.SplitN(q, ":", 2)
	k := strings.ToLower(strings.TrimSpace(parts[0]))
	v := strings.TrimSpace(parts[1])

	switch k {
	case "src_ip", "dst_ip", "action", "threat_flag", "proto", "device_ip", "tenant":
		return k, strings.ToLower(v)
	}
	return "", ""
}

// In-Memory Shunned IP Registry
type ShunEntry struct {
	TS     int64  `json:"ts"`
	Reason string `json:"reason"`
	By     string `json:"by"`
}

var (
	shunMu  sync.RWMutex
	shunMap = map[string]ShunEntry{}
)

func AddShun(ip, reason, by string) ShunEntry {
	shunMu.Lock()
	defer shunMu.Unlock()
	e := ShunEntry{
		TS:     time.Now().Unix(),
		Reason: reason,
		By:     by,
	}
	shunMap[ip] = e
	return e
}

func ListShuns() map[string]ShunEntry {
	shunMu.RLock()
	defer shunMu.RUnlock()
	res := make(map[string]ShunEntry, len(shunMap))
	for k, v := range shunMap {
		res[k] = v
	}
	return res
}

