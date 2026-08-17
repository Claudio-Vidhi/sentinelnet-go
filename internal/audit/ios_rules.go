package audit

import (
	"fmt"
	"strconv"
	"strings"
)

var (
	iosDefaultCommunities = map[string]bool{"public": true, "private": true}
)

const (
	maxExecTimeoutMin = 10
	maxSSHTimeoutS    = 60
	maxSSHRetries     = 3
	minLogBuffer      = 64000
	minSNMPAESBits    = 128
)

func iosEv(l IosLine, note ...string) Evidence {
	ctx := strings.Join(l.Path, " / ")
	if ctx == "" && len(note) > 0 {
		ctx = note[0]
	}
	return Evidence{
		Line:    l.Line,
		Text:    l.Text,
		Context: ctx,
	}
}

func iosEvList(lines []IosLine) []Evidence {
	res := make([]Evidence, len(lines))
	for i, l := range lines {
		res[i] = iosEv(l)
	}
	return res
}

func iosGuard(cfg IosConfig) *RuleOutcome {
	if cfg.IsEmpty() {
		return &RuleOutcome{Status: StatusUnknown, Message: "ios.empty"}
	}
	return nil
}

func checkExecTimeout(cfg IosConfig, prefix, key string) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	found := IosBlocksMatching(cfg, prefix)
	if len(found) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: key + ".absent"}
	}
	var ev []Evidence
	for _, b := range found {
		t := IosChild(b.Kids, "exec-timeout")
		if t == nil {
			ev = append(ev, Absent("ev.not_set_default", b.Header, map[string]any{"what": "exec-timeout"}))
			continue
		}
		mins := -1
		secs := 0
		if len(t.Words) > 1 {
			if m, err := strconv.Atoi(t.Words[1]); err == nil {
				mins = m
			}
		}
		if len(t.Words) > 2 {
			if s, err := strconv.Atoi(t.Words[2]); err == nil {
				secs = s
			}
		}
		if mins < 0 {
			ev = append(ev, iosEv(*t, b.Header))
		} else if mins == 0 && secs == 0 {
			ev = append(ev, iosEv(*t, b.Header))
		} else if mins > maxExecTimeoutMin || (mins == maxExecTimeoutMin && secs > 0) {
			ev = append(ev, iosEv(*t, b.Header))
		}
	}
	params := map[string]any{"count": len(ev), "max": maxExecTimeoutMin}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: key + ".bad", Evidence: ev, Params: params}
	}
	return RuleOutcome{Status: StatusPass, Message: key + ".ok", Params: params}
}

func checkBanner(cfg IosConfig, kind string) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if len(IosFind(cfg, "banner "+kind)) > 0 {
		return RuleOutcome{Status: StatusPass, Message: "ios.banner.ok", Params: map[string]any{"kind": kind}}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.banner.absent",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "banner " + kind})},
		Params:   map[string]any{"kind": kind},
	}
}

func checkServiceOff(cfg IosConfig, service, key string) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if IosHasTop(cfg, "no "+service) {
		return RuleOutcome{Status: StatusPass, Message: "ios.service.ok", Params: map[string]any{"service": service}}
	}
	enabled := IosFindTop(cfg, service)
	if len(enabled) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  key + ".enabled",
			Evidence: []Evidence{iosEv(enabled[0])},
			Params:   map[string]any{"service": service},
		}
	}
	return RuleOutcome{
		Status:   StatusWarn,
		Message:  "ios.service.not_disabled",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "no " + service})},
		Params:   map[string]any{"service": service},
	}
}

func CheckIOSAAANewModel(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if IosHasTop(cfg, "no aaa new-model") {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.aaa.disabled",
			Evidence: []Evidence{iosEv(IosFindTop(cfg, "no aaa new-model")[0])},
		}
	}
	if IosHasTop(cfg, "aaa new-model") {
		return RuleOutcome{Status: StatusPass, Message: "ios.aaa.ok"}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.aaa.absent",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "aaa new-model"})},
	}
}

func CheckIOSAAAAuthenticationLogin(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if !IosHasTop(cfg, "aaa new-model") {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.aaa.not_applicable_login"}
	}
	hits := IosFindTop(cfg, "aaa authentication login")
	if len(hits) == 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.aaa_login.absent",
			Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "aaa authentication login"})},
		}
	}
	var weak []Evidence
	for _, l := range hits {
		if len(l.Words) > 0 && l.Words[len(l.Words)-1] == "none" {
			weak = append(weak, iosEv(l))
		}
	}
	if len(weak) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "ios.aaa_login.none", Evidence: weak}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.aaa_login.ok", Params: map[string]any{"count": len(hits)}}
}

func CheckIOSAAAAccountingCommands(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if !IosHasTop(cfg, "aaa new-model") {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.aaa.not_applicable_accounting"}
	}
	if len(IosFindTop(cfg, "aaa accounting commands 15")) > 0 {
		return RuleOutcome{Status: StatusPass, Message: "ios.accounting.ok"}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.accounting.absent",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "aaa accounting commands 15"})},
	}
}

func CheckIOSVTYTransportSSH(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	vtys := IosBlocksMatching(cfg, "line vty")
	if len(vtys) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.vty.absent"}
	}
	var ev []Evidence
	for _, b := range vtys {
		t := IosChild(b.Kids, "transport input")
		if t == nil {
			ev = append(ev, Absent("ev.no_transport_input", b.Header, nil))
			continue
		}
		allowed := make(map[string]bool)
		if len(t.Words) > 2 {
			for _, w := range t.Words[2:] {
				allowed[w] = true
			}
		}
		hasInsecure := false
		for k := range allowed {
			if k != "ssh" && k != "none" {
				hasInsecure = true
				break
			}
		}
		if hasInsecure {
			ev = append(ev, iosEv(*t, b.Header))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.vty_transport.insecure",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.vty_transport.ok"}
}

func CheckIOSVTYAccessClass(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	vtys := IosBlocksMatching(cfg, "line vty")
	if len(vtys) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.vty.absent"}
	}
	var ev []Evidence
	for _, b := range vtys {
		if IosChild(b.Kids, "access-class") == nil {
			ev = append(ev, Absent("ev.no_directive", b.Header, map[string]any{"what": "access-class <ACL> in"}))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.vty_acl.missing",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.vty_acl.ok"}
}

func CheckIOSVTYExecTimeout(cfg IosConfig) RuleOutcome {
	return checkExecTimeout(cfg, "line vty", "ios.vty_timeout")
}

func CheckIOSConsoleExecTimeout(cfg IosConfig) RuleOutcome {
	return checkExecTimeout(cfg, "line con", "ios.con_timeout")
}

func CheckIOSAuxNoExec(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	aux := IosBlocksMatching(cfg, "line aux")
	if len(aux) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.aux.absent"}
	}
	var ev []Evidence
	for _, b := range aux {
		if IosChild(b.Kids, "no exec") == nil {
			ev = append(ev, Absent("ev.no_directive", b.Header, map[string]any{"what": "no exec"}))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "ios.aux.exec_active", Evidence: ev}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.aux.ok"}
}

func CheckIOSLocalUserPrivilege(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	users := IosFindTop(cfg, "username ")
	if len(users) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.users.absent"}
	}
	var ev []Evidence
	for _, u := range users {
		if strings.Contains(u.Lower, "privilege 15") {
			ev = append(ev, iosEv(u))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.user_priv.high",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.user_priv.ok"}
}

func CheckIOSBannerLogin(cfg IosConfig) RuleOutcome {
	return checkBanner(cfg, "login")
}

func CheckIOSBannerMOTD(cfg IosConfig) RuleOutcome {
	return checkBanner(cfg, "motd")
}

func CheckIOSEnableSecret(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	weak := IosFindTop(cfg, "enable password")
	secret := IosFindTop(cfg, "enable secret")
	if len(weak) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.enable.password",
			Evidence: iosEvList(weak),
		}
	}
	if len(secret) > 0 {
		return RuleOutcome{Status: StatusPass, Message: "ios.enable.ok"}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.enable.absent",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "enable secret"})},
	}
}

func CheckIOSServicePasswordEncryption(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if IosHasTop(cfg, "no service password-encryption") {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.pw_encryption.disabled",
			Evidence: []Evidence{iosEv(IosFindTop(cfg, "no service password-encryption")[0])},
		}
	}
	if IosHasTop(cfg, "service password-encryption") {
		return RuleOutcome{Status: StatusPass, Message: "ios.pw_encryption.ok"}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.pw_encryption.absent",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "service password-encryption"})},
	}
}

func CheckIOSUsernameSecret(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	users := IosFindTop(cfg, "username ")
	if len(users) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.users.absent"}
	}
	var ev []Evidence
	for _, u := range users {
		if !strings.Contains(u.Lower+" ", " secret ") {
			ev = append(ev, iosEv(u))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.user_secret.password",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.user_secret.ok"}
}

func CheckIOSSNMPDefaultCommunity(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	comms := IosFindTop(cfg, "snmp-server community")
	if len(comms) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.snmp.absent"}
	}
	var ev []Evidence
	for _, c := range comms {
		if len(c.Words) > 2 && iosDefaultCommunities[c.Words[2]] {
			ev = append(ev, iosEv(c))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.snmp_default.found",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.snmp_default.ok"}
}

func CheckIOSSNMPReadWrite(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	comms := IosFindTop(cfg, "snmp-server community")
	if len(comms) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.snmp.absent"}
	}
	var ev []Evidence
	for _, c := range comms {
		if len(c.Words) > 3 {
			for _, w := range c.Words[3:] {
				if w == "rw" {
					ev = append(ev, iosEv(c))
					break
				}
			}
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.snmp_rw.found",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.snmp_rw.ok"}
}

func CheckIOSSNMPCommunityACL(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	comms := IosFindTop(cfg, "snmp-server community")
	if len(comms) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.snmp.absent"}
	}
	var ev []Evidence
	for _, c := range comms {
		var tail []string
		if len(c.Words) > 3 {
			for _, w := range c.Words[3:] {
				if w != "ro" && w != "rw" && w != "view" {
					tail = append(tail, w)
				}
			}
		}
		if len(tail) == 0 {
			ev = append(ev, iosEv(c))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.snmp_acl.missing",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.snmp_acl.ok"}
}

func CheckIOSSNMPV3Privacy(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	groups := IosFindTop(cfg, "snmp-server group")
	users := IosFindTop(cfg, "snmp-server user")
	if len(groups) == 0 && len(users) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.snmpv3.absent"}
	}
	var ev []Evidence
	for _, grp := range groups {
		hasV3 := false
		hasPriv := false
		for _, w := range grp.Words {
			if w == "v3" {
				hasV3 = true
			}
			if w == "priv" {
				hasPriv = true
			}
		}
		if hasV3 && !hasPriv {
			ev = append(ev, iosEv(grp))
		}
	}
	for _, usr := range users {
		hasV3 := false
		hasPriv := false
		hasAes := false
		aesIdx := -1
		for i, w := range usr.Words {
			if w == "v3" {
				hasV3 = true
			}
			if w == "priv" {
				hasPriv = true
			}
			if w == "aes" {
				hasAes = true
				aesIdx = i
			}
		}
		if !hasV3 {
			continue
		}
		if !hasPriv || !hasAes {
			ev = append(ev, iosEv(usr))
			continue
		}
		bits := -1
		if aesIdx+1 < len(usr.Words) {
			if b, err := strconv.Atoi(usr.Words[aesIdx+1]); err == nil {
				bits = b
			}
		}
		if bits < minSNMPAESBits {
			ev = append(ev, iosEv(usr))
		}
	}
	params := map[string]any{"count": len(ev), "bits": minSNMPAESBits}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "ios.snmpv3.weak", Evidence: ev, Params: params}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.snmpv3.ok", Params: params}
}

func CheckIOSSSHVersion(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "ip ssh version")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "ios.ssh_version.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": "ip ssh version 2"}),
			},
		}
	}
	if len(rec.Words) > 0 && rec.Words[len(rec.Words)-1] == "2" {
		return RuleOutcome{Status: StatusPass, Message: "ios.ssh_version.ok"}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.ssh_version.v1",
		Evidence: []Evidence{iosEv(*rec)},
	}
}

func CheckIOSSSHTimeout(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "ip ssh time-out", "ip ssh timeout")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "ios.ssh_timeout.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": fmt.Sprintf("ip ssh time-out %d", maxSSHTimeoutS)}),
			},
		}
	}
	val, err := strconv.Atoi(rec.Words[len(rec.Words)-1])
	if err != nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.ssh_timeout.unreadable",
			Evidence: []Evidence{iosEv(*rec)},
		}
	}
	if val > maxSSHTimeoutS {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.ssh_timeout.too_high",
			Evidence: []Evidence{iosEv(*rec)},
			Params:   map[string]any{"value": val, "max": maxSSHTimeoutS},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "ios.ssh_timeout.ok",
		Params:  map[string]any{"value": val},
	}
}

func CheckIOSSSHAuthRetries(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "ip ssh authentication-retries")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "ios.ssh_retries.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": fmt.Sprintf("ip ssh authentication-retries %d", maxSSHRetries)}),
			},
		}
	}
	val, err := strconv.Atoi(rec.Words[len(rec.Words)-1])
	if err != nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.ssh_retries.unreadable",
			Evidence: []Evidence{iosEv(*rec)},
		}
	}
	if val > maxSSHRetries {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.ssh_retries.too_high",
			Evidence: []Evidence{iosEv(*rec)},
			Params:   map[string]any{"value": val, "max": maxSSHRetries},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "ios.ssh_retries.ok",
		Params:  map[string]any{"value": val},
	}
}

func CheckIOSDomainName(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "ip domain-name", "ip domain name")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "ios.domain.absent",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": "ip domain-name"}),
			},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "ios.domain.ok",
		Params:  map[string]any{"domain": rec.Words[len(rec.Words)-1]},
	}
}

func CheckIOSCDP(cfg IosConfig) RuleOutcome {
	return checkServiceOff(cfg, "cdp run", "ios.cdp")
}

func CheckIOSServiceDHCP(cfg IosConfig) RuleOutcome {
	return checkServiceOff(cfg, "service dhcp", "ios.dhcp")
}

func CheckIOSServicePAD(cfg IosConfig) RuleOutcome {
	return checkServiceOff(cfg, "service pad", "ios.pad")
}

func CheckIOSTCPKeepalives(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	var missing []string
	for _, d := range []string{"in", "out"} {
		if !IosHasTop(cfg, "service tcp-keepalives-"+d) {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		var ev []Evidence
		var dirs []string
		for _, d := range missing {
			ev = append(ev, Absent("ev.no_directive", "", map[string]any{"what": "service tcp-keepalives-" + d}))
			dirs = append(dirs, "tcp-keepalives-"+d)
		}
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.keepalive.missing",
			Evidence: ev,
			Params:   map[string]any{"directives": strings.Join(dirs, ", ")},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.keepalive.ok"}
}

func CheckIOSLoggingHost(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	hosts := IosFindTop(cfg, "logging host", "logging server")
	var legacy []IosLine
	for _, l := range IosFindTop(cfg, "logging ") {
		if len(l.Words) == 2 && len(l.Words[1]) > 0 && l.Words[1][0] >= '0' && l.Words[1][0] <= '9' {
			legacy = append(legacy, l)
		}
	}
	total := len(hosts) + len(legacy)
	if total > 0 {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "ios.log_host.ok",
			Params:  map[string]any{"count": total},
		}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.log_host.absent",
		Evidence: []Evidence{Absent("ev.no_directive", "", map[string]any{"what": "logging host"})},
	}
}

func CheckIOSLoggingBuffered(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "logging buffered")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "ios.log_buffer.absent",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": fmt.Sprintf("logging buffered %d", minLogBuffer)}),
			},
		}
	}
	var size *int
	for i := 2; i < len(rec.Words); i++ {
		if v, err := strconv.Atoi(rec.Words[i]); err == nil {
			size = &v
			break
		}
	}
	if size == nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.log_buffer.no_size",
			Evidence: []Evidence{iosEv(*rec)},
		}
	}
	if *size < minLogBuffer {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.log_buffer.small",
			Evidence: []Evidence{iosEv(*rec)},
			Params:   map[string]any{"size": *size, "min": minLogBuffer},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "ios.log_buffer.ok",
		Params:  map[string]any{"size": *size},
	}
}

func CheckIOSLoggingConsole(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "logging console")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "ios.log_console.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": "logging console critical"}),
			},
		}
	}
	level := rec.Words[len(rec.Words)-1]
	if level == "critical" || level == "2" || level == "emergencies" || level == "0" || level == "alerts" || level == "1" {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "ios.log_console.ok",
			Params:  map[string]any{"level": level},
		}
	}
	return RuleOutcome{
		Status:   StatusWarn,
		Message:  "ios.log_console.verbose",
		Evidence: []Evidence{iosEv(*rec)},
		Params:   map[string]any{"level": level},
	}
}

func CheckIOSLoggingTrap(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	rec := IosFirstTop(cfg, "logging trap")
	if rec == nil {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "ios.log_trap.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": "logging trap informational"}),
			},
		}
	}
	level := rec.Words[len(rec.Words)-1]
	if level == "informational" || level == "6" || level == "debugging" || level == "7" {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "ios.log_trap.ok",
			Params:  map[string]any{"level": level},
		}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "ios.log_trap.too_strict",
		Evidence: []Evidence{iosEv(*rec)},
		Params:   map[string]any{"level": level},
	}
}

func CheckIOSServiceTimestamps(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	stamps := IosFindTop(cfg, "service timestamps")
	if len(stamps) == 0 {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "ios.timestamps.absent",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": "service timestamps log datetime"}),
			},
		}
	}
	var bad []Evidence
	for _, l := range stamps {
		hasDatetime := false
		for _, w := range l.Words {
			if w == "datetime" {
				hasDatetime = true
				break
			}
		}
		if !hasDatetime {
			bad = append(bad, iosEv(l))
		}
	}
	if len(bad) > 0 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.timestamps.uptime",
			Evidence: bad,
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.timestamps.ok"}
}

func CheckIOSLoggingSourceInterface(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if IosHasTop(cfg, "logging source-interface") {
		return RuleOutcome{Status: StatusPass, Message: "ios.log_source.ok"}
	}
	return RuleOutcome{
		Status:  StatusWarn,
		Message: "ios.log_source.absent",
		Evidence: []Evidence{
			Absent("ev.no_directive", "", map[string]any{"what": "logging source-interface"}),
		},
	}
}

func CheckIOSLoginLogging(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	var missing []string
	for _, d := range []string{"on-failure", "on-success"} {
		if !IosHasTop(cfg, "login "+d+" log") {
			missing = append(missing, d)
		}
	}
	if len(missing) > 0 {
		var ev []Evidence
		var dirs []string
		for _, d := range missing {
			ev = append(ev, Absent("ev.no_directive", "", map[string]any{"what": "login " + d + " log"}))
			dirs = append(dirs, "login "+d+" log")
		}
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "ios.login_log.missing",
			Evidence: ev,
			Params:   map[string]any{"directives": strings.Join(dirs, ", ")},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.login_log.ok"}
}

func CheckIOSNTPServers(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	servers := IosFindTop(cfg, "ntp server")
	if len(servers) == 0 {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "ios.ntp.absent",
			Evidence: []Evidence{
				Absent("ev.no_directive", "", map[string]any{"what": "ntp server"}),
			},
		}
	}
	if len(servers) < 2 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.ntp.single",
			Evidence: []Evidence{iosEv(servers[0])},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "ios.ntp.ok",
		Params:  map[string]any{"count": len(servers)},
	}
}

func CheckIOSNTPAuthentication(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	if len(IosFindTop(cfg, "ntp server")) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.ntp_auth.not_applicable"}
	}
	var ev []Evidence
	if !IosHasTop(cfg, "ntp authenticate") {
		ev = append(ev, Absent("ev.no_directive", "", map[string]any{"what": "ntp authenticate"}))
	}
	if !IosHasTop(cfg, "ntp trusted-key") {
		ev = append(ev, Absent("ev.no_directive", "", map[string]any{"what": "ntp trusted-key"}))
	}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "ios.ntp_auth.missing", Evidence: ev}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.ntp_auth.ok"}
}

func CheckIOSSourceRoute(cfg IosConfig) RuleOutcome {
	return checkServiceOff(cfg, "ip source-route", "ios.source_route")
}

func CheckIOSProxyARP(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	allIfaces := IosBlocksMatching(cfg, "interface")
	var ifaces []IosBlock
	for _, b := range allIfaces {
		if IosChild(b.Kids, "ip address") != nil {
			ifaces = append(ifaces, b)
		}
	}
	if len(ifaces) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "ios.proxy_arp.no_ip_iface"}
	}
	var ev []Evidence
	for _, b := range ifaces {
		if IosChild(b.Kids, "no ip proxy-arp") == nil {
			ev = append(ev, Absent("ev.not_set_default_on", b.Header, map[string]any{"what": "no ip proxy-arp"}))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "ios.proxy_arp.enabled",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "ios.proxy_arp.ok"}
}

func CheckIOSTunnelInterfaces(cfg IosConfig) RuleOutcome {
	if g := iosGuard(cfg); g != nil {
		return *g
	}
	tunnels := IosBlocksMatching(cfg, "interface tunnel")
	if len(tunnels) == 0 {
		return RuleOutcome{Status: StatusPass, Message: "ios.tunnel.none"}
	}
	var ev []Evidence
	for _, b := range tunnels {
		ev = append(ev, Evidence{
			Line:    0,
			Text:    b.Header,
			Context: "interface",
		})
	}
	return RuleOutcome{
		Status:   StatusWarn,
		Message:  "ios.tunnel.present",
		Evidence: ev,
		Params:   map[string]any{"count": len(tunnels)},
	}
}
