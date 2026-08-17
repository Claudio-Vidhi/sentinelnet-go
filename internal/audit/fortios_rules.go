package audit

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

var (
	insecureAccess = map[string]bool{"telnet": true, "http": true}
	weakTLS        = map[string]bool{"sslv3": true, "tlsv1-0": true, "tlsv1-1": true, "tlsv1.0": true, "tlsv1.1": true}
	anyAddr        = map[string]bool{"all": true, "any": true}
	anyService     = map[string]bool{"all": true, "any": true}
	adminPorts     = []int{22, 3389}
	builtinAdminSvcs = map[string]bool{"ssh": true, "rdp": true}
	defaultCommunities = map[string]bool{"public": true, "private": true}
	securityProfiles = []string{
		"av-profile", "ips-sensor", "webfilter-profile",
		"application-list", "dnsfilter-profile",
		"ssl-ssh-profile", "file-filter-profile",
		"emailfilter-profile",
	}
)

const maxAdminTimeout = 5
const minPasswordLength = 14
const maxLockoutThreshold = 3
const minLockoutDuration = 900

func fgtCtx(parts ...string) string {
	var non []string
	for _, p := range parts {
		if p != "" {
			non = append(non, p)
		}
	}
	return strings.Join(non, " / ")
}

func fgtEv1(rec *ConfigRecord, ctx ...string) Evidence {
	if rec == nil {
		return Evidence{}
	}
	return Evidence{
		Line:    rec.Line,
		Text:    strings.TrimSpace(rec.Raw),
		Context: fgtCtx(ctx...),
	}
}

func fgtIntValue(rec *ConfigRecord) *int {
	if rec == nil || len(rec.Values) == 0 {
		return nil
	}
	v, err := strconv.Atoi(rec.Values[0])
	if err != nil {
		return nil
	}
	return &v
}

func fgtFlag(cfg ParsedConfig, section, key, want, prefix string, missingStatus, badStatus string) RuleOutcome {
	rec := Setting(cfg, section, key)
	if rec == nil {
		if !SectionPresent(cfg, section) {
			return RuleOutcome{Status: StatusUnknown, Message: prefix + ".no_section"}
		}
		return RuleOutcome{
			Status:  missingStatus,
			Message: prefix + ".not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", fgtCtx(section), map[string]any{"what": fmt.Sprintf("set %s %s", key, want)}),
			},
		}
	}
	if len(rec.Values) > 0 && strings.ToLower(rec.Values[0]) == want {
		return RuleOutcome{Status: StatusPass, Message: prefix + ".ok"}
	}
	return RuleOutcome{
		Status:   badStatus,
		Message:  prefix + ".bad",
		Evidence: []Evidence{fgtEv1(rec, section)},
	}
}

func policyValues(recs []ConfigRecord) map[string][]string {
	out := make(map[string][]string)
	for _, r := range recs {
		for _, v := range r.Values {
			out[r.Key] = append(out[r.Key], strings.ToLower(v))
		}
	}
	return out
}

func policyLine(recs []ConfigRecord, prefer string) (int, string) {
	for _, r := range recs {
		if r.Key == prefer {
			return r.Line, strings.TrimSpace(r.Raw)
		}
	}
	if len(recs) > 0 {
		return recs[0].Line, strings.TrimSpace(recs[0].Raw)
	}
	return 0, ""
}

func WanInterfaces(cfg ParsedConfig) map[string]bool {
	ifaces := SectionEntries(cfg, "system interface")
	named := make(map[string]bool)
	for name, recs := range ifaces {
		for _, r := range recs {
			if r.Key == "role" && len(r.Values) > 0 && strings.ToLower(r.Values[0]) == "wan" {
				named[strings.ToLower(name)] = true
			}
		}
	}
	if len(named) > 0 {
		return named
	}
	res := make(map[string]bool)
	for n := range ifaces {
		low := strings.ToLower(n)
		if strings.HasPrefix(low, "wan") || low == "port1" {
			res[low] = true
		}
	}
	return res
}

func rangeHitsAdminPort(token string) bool {
	token = strings.Split(token, ":")[0]
	for _, part := range strings.Split(token, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		var lo, hi int
		if strings.Contains(part, "-") {
			dash := strings.SplitN(part, "-", 2)
			lo, _ = strconv.Atoi(dash[0])
			hi, _ = strconv.Atoi(dash[1])
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			lo, hi = p, p
		}
		for _, ap := range adminPorts {
			if lo <= ap && ap <= hi {
				return true
			}
		}
	}
	return false
}

func AdminServiceNames(cfg ParsedConfig) map[string]bool {
	names := make(map[string]bool)
	for k := range builtinAdminSvcs {
		names[k] = true
	}
	for name, recs := range SectionEntries(cfg, "firewall service custom") {
		for _, r := range recs {
			if r.Key == "tcp-portrange" {
				for _, v := range r.Values {
					if rangeHitsAdminPort(v) {
						names[strings.ToLower(name)] = true
						break
					}
				}
			}
		}
	}
	return names
}

func isUnrestrictedTrusthost(values []string) bool {
	if len(values) == 0 {
		return false
	}
	uniq := make(map[string]bool)
	for _, v := range values {
		uniq[strings.ToLower(v)] = true
	}
	if len(uniq) == 1 && (uniq["0.0.0.0"] || uniq["0.0.0.0/0"]) {
		return true
	}
	return false
}

func acceptPolicies(cfg ParsedConfig) []struct {
	Pid  string
	Recs []ConfigRecord
} {
	policies := SectionEntries(cfg, "firewall policy")
	var pids []string
	for pid := range policies {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool {
		if len(pids[i]) != len(pids[j]) {
			return len(pids[i]) < len(pids[j])
		}
		return pids[i] < pids[j]
	})
	var out []struct {
		Pid  string
		Recs []ConfigRecord
	}
	for _, pid := range pids {
		vals := policyValues(policies[pid])
		hasAccept := false
		for _, act := range vals["action"] {
			if act == "accept" {
				hasAccept = true
				break
			}
		}
		if hasAccept {
			out = append(out, struct {
				Pid  string
				Recs []ConfigRecord
			}{Pid: pid, Recs: policies[pid]})
		}
	}
	return out
}

func CheckFortiOSManagementProtocols(cfg ParsedConfig) RuleOutcome {
	ifaces := SectionEntries(cfg, "system interface")
	if len(ifaces) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.mgmt_proto.no_section"}
	}
	var names []string
	for n := range ifaces {
		names = append(names, n)
	}
	sort.Strings(names)

	var ev []Evidence
	for _, name := range names {
		for _, r := range ifaces[name] {
			if r.Key != "allowaccess" {
				continue
			}
			hasBad := false
			for _, v := range r.Values {
				if insecureAccess[strings.ToLower(v)] {
					hasBad = true
					break
				}
			}
			if hasBad {
				ev = append(ev, fgtEv1(&r, "system interface", name))
			}
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.mgmt_proto.insecure",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.mgmt_proto.ok"}
}

func CheckFortiOSTLSVersion(cfg ParsedConfig) RuleOutcome {
	rec := Setting(cfg, "system global", "ssl-min-proto-version")
	if rec == nil {
		rec = Setting(cfg, "system global", "admin-https-ssl-versions")
	}
	if rec == nil {
		if !SectionPresent(cfg, "system global") {
			return RuleOutcome{Status: StatusUnknown, Message: "fos.tls.no_section"}
		}
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.tls.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": "set ssl-min-proto-version TLSv1-2"}),
			},
		}
	}
	var weakFound []string
	for _, v := range rec.Values {
		low := strings.ToLower(v)
		if weakTLS[low] {
			weakFound = append(weakFound, v)
		}
	}
	if len(weakFound) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.tls.weak",
			Evidence: []Evidence{fgtEv1(rec, "system global")},
			Params:   map[string]any{"versions": strings.Join(weakFound, ", ")},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.tls.ok"}
}

func CheckFortiOSIdleTimeout(cfg ParsedConfig) RuleOutcome {
	rec := Setting(cfg, "system global", "admintimeout")
	if rec == nil {
		if !SectionPresent(cfg, "system global") {
			return RuleOutcome{Status: StatusUnknown, Message: "fos.idle.no_section"}
		}
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.idle.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": fmt.Sprintf("set admintimeout %d", maxAdminTimeout)}),
			},
		}
	}
	val := fgtIntValue(rec)
	if val == nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "fos.idle.unreadable",
			Evidence: []Evidence{fgtEv1(rec, "system global")},
		}
	}
	if *val == 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.idle.disabled",
			Evidence: []Evidence{fgtEv1(rec, "system global")},
		}
	}
	if *val > maxAdminTimeout {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.idle.too_high",
			Evidence: []Evidence{fgtEv1(rec, "system global")},
			Params:   map[string]any{"value": *val, "max": maxAdminTimeout},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "fos.idle.ok",
		Params:  map[string]any{"value": *val},
	}
}

func CheckFortiOSStrongCrypto(cfg ParsedConfig) RuleOutcome {
	return fgtFlag(cfg, "system global", "strong-crypto", "enable", "fos.strong_crypto", StatusWarn, StatusWarn)
}

func CheckFortiOSAnyAnyPolicy(cfg ParsedConfig) RuleOutcome {
	policies := SectionEntries(cfg, "firewall policy")
	if len(policies) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_section"}
	}
	var pids []string
	for pid := range policies {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool {
		if len(pids[i]) != len(pids[j]) {
			return len(pids[i]) < len(pids[j])
		}
		return pids[i] < pids[j]
	})

	var ev []Evidence
	for _, pid := range pids {
		vals := policyValues(policies[pid])
		hasAccept := false
		for _, a := range vals["action"] {
			if a == "accept" {
				hasAccept = true
				break
			}
		}
		if !hasAccept {
			continue
		}
		hasSrcAll, hasDstAll, hasSvcAll := false, false, false
		for _, s := range vals["srcaddr"] {
			if anyAddr[s] {
				hasSrcAll = true
				break
			}
		}
		for _, d := range vals["dstaddr"] {
			if anyAddr[d] {
				hasDstAll = true
				break
			}
		}
		for _, sv := range vals["service"] {
			if anyService[sv] {
				hasSvcAll = true
				break
			}
		}
		if hasSrcAll && hasDstAll && hasSvcAll {
			line, raw := policyLine(policies[pid], "action")
			ev = append(ev, Evidence{
				Line:    line,
				Text:    raw,
				Context: fgtCtx("firewall policy", pid),
			})
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.any_any.found",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.any_any.ok"}
}

func CheckFortiOSBoundaryProtection(cfg ParsedConfig) RuleOutcome {
	policies := SectionEntries(cfg, "firewall policy")
	if len(policies) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_section"}
	}
	wan := WanInterfaces(cfg)
	if len(wan) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_wan"}
	}
	var pids []string
	for pid := range policies {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool {
		if len(pids[i]) != len(pids[j]) {
			return len(pids[i]) < len(pids[j])
		}
		return pids[i] < pids[j]
	})

	var ev []Evidence
	for _, pid := range pids {
		vals := policyValues(policies[pid])
		hasAccept := false
		for _, a := range vals["action"] {
			if a == "accept" {
				hasAccept = true
				break
			}
		}
		if !hasAccept {
			continue
		}
		srcFromWan := false
		for _, si := range vals["srcintf"] {
			if wan[si] {
				srcFromWan = true
				break
			}
		}
		if !srcFromWan {
			continue
		}
		dstAny := false
		for _, da := range vals["dstaddr"] {
			if anyAddr[da] {
				dstAny = true
				break
			}
		}
		if dstAny {
			line, raw := policyLine(policies[pid], "action")
			ev = append(ev, Evidence{
				Line:    line,
				Text:    raw,
				Context: fgtCtx("firewall policy", pid),
			})
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.boundary.found",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.boundary.ok"}
}

func CheckFortiOSInboundAdminPorts(cfg ParsedConfig) RuleOutcome {
	policies := SectionEntries(cfg, "firewall policy")
	if len(policies) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_section"}
	}
	wan := WanInterfaces(cfg)
	if len(wan) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_wan"}
	}
	adminServices := AdminServiceNames(cfg)

	var pids []string
	for pid := range policies {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool {
		if len(pids[i]) != len(pids[j]) {
			return len(pids[i]) < len(pids[j])
		}
		return pids[i] < pids[j]
	})

	var ev []Evidence
	for _, pid := range pids {
		vals := policyValues(policies[pid])
		hasAccept := false
		for _, a := range vals["action"] {
			if a == "accept" {
				hasAccept = true
				break
			}
		}
		if !hasAccept {
			continue
		}
		fromWan := false
		for _, si := range vals["srcintf"] {
			if wan[si] {
				fromWan = true
				break
			}
		}
		if !fromWan {
			continue
		}
		srcAny := false
		for _, sa := range vals["srcaddr"] {
			if anyAddr[sa] {
				srcAny = true
				break
			}
		}
		if !srcAny {
			continue
		}
		hasAdminSvc := false
		for _, svc := range vals["service"] {
			if adminServices[svc] {
				hasAdminSvc = true
				break
			}
		}
		if hasAdminSvc {
			line, raw := policyLine(policies[pid], "service")
			ev = append(ev, Evidence{
				Line:    line,
				Text:    raw,
				Context: fgtCtx("firewall policy", pid),
			})
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.admin_ports.exposed",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.admin_ports.ok"}
}

func CheckFortiOSAdminTrusthost(cfg ParsedConfig) RuleOutcome {
	admins := SectionEntries(cfg, "system admin")
	if len(admins) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.trusthost.no_section"}
	}
	var names []string
	for n := range admins {
		names = append(names, n)
	}
	sort.Strings(names)

	var ev []Evidence
	for _, name := range names {
		recs := admins[name]
		var hosts []ConfigRecord
		for _, r := range recs {
			if strings.HasPrefix(r.Key, "trusthost") {
				hosts = append(hosts, r)
			}
		}
		if len(hosts) == 0 {
			ev = append(ev, Absent("ev.no_trusthost", fgtCtx("system admin", name), nil))
			continue
		}
		for _, r := range hosts {
			if isUnrestrictedTrusthost(r.Values) {
				ev = append(ev, fgtEv1(&r, "system admin", name))
			}
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.trusthost.unrestricted",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.trusthost.ok"}
}

func CheckFortiOSSNMPCommunity(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system snmp community") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.snmp_default.no_section"}
	}
	communities := SectionEntries(cfg, "system snmp community")
	var names []string
	for n := range communities {
		names = append(names, n)
	}
	sort.Strings(names)

	var ev []Evidence
	for _, name := range names {
		for _, r := range communities[name] {
			if r.Key == "name" && len(r.Values) > 0 && defaultCommunities[strings.ToLower(r.Values[0])] {
				ev = append(ev, fgtEv1(&r, "system snmp community", name))
			}
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.snmp_default.found",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.snmp_default.ok"}
}

func CheckFortiOSSyslog(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "log syslogd setting") {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "fos.syslog.no_section",
			Evidence: []Evidence{
				Absent("ev.no_block", "log syslogd setting", map[string]any{"what": "config log syslogd setting"}),
			},
		}
	}
	status := Setting(cfg, "log syslogd setting", "status")
	server := Setting(cfg, "log syslogd setting", "server")
	var ev []Evidence
	if status == nil || len(status.Values) == 0 || strings.ToLower(status.Values[0]) != "enable" {
		if status != nil {
			ev = append(ev, fgtEv1(status, "log syslogd setting"))
		} else {
			ev = append(ev, Absent("ev.no_directive", fgtCtx("log syslogd setting"), map[string]any{"what": "set status enable"}))
		}
	}
	if server == nil || len(server.Values) == 0 {
		if server != nil {
			ev = append(ev, fgtEv1(server, "log syslogd setting"))
		} else {
			ev = append(ev, Absent("ev.no_directive", fgtCtx("log syslogd setting"), map[string]any{"what": "set server <ip>"}))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "fos.syslog.incomplete", Evidence: ev}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.syslog.ok"}
}

func CheckFortiOSVendorDefaults(cfg ParsedConfig) RuleOutcome {
	admins := SectionEntries(cfg, "system admin")
	hasPolicyBlock := SectionPresent(cfg, "system password-policy")
	if len(admins) == 0 && !hasPolicyBlock {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.defaults.no_section"}
	}
	var ev []Evidence
	var names []string
	for n := range admins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.ToLower(name) == "admin" {
			recs := admins[name]
			line := 0
			if len(recs) > 0 {
				line = recs[0].Line
			}
			ev = append(ev, Evidence{
				Line:    line,
				Text:    "",
				Context: fgtCtx("system admin", name),
				Message: "ev.default_admin_account",
			})
		}
	}
	if hasPolicyBlock {
		status := Setting(cfg, "system password-policy", "status")
		if status == nil || len(status.Values) == 0 || strings.ToLower(status.Values[0]) != "enable" {
			if status != nil {
				ev = append(ev, fgtEv1(status, "system password-policy"))
			} else {
				ev = append(ev, Absent("ev.no_directive", fgtCtx("system password-policy"), map[string]any{"what": "set status enable"}))
			}
		}
	} else {
		ev = append(ev, Absent("ev.no_block", fgtCtx("system password-policy"), map[string]any{"what": "config system password-policy"}))
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.defaults.found",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.defaults.ok"}
}

func CheckFortiOSDNSConfigured(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system dns") {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "fos.dns.no_section",
			Evidence: []Evidence{
				Absent("ev.no_block", "system dns", map[string]any{"what": "config system dns"}),
			},
		}
	}
	p := Setting(cfg, "system dns", "primary")
	s := Setting(cfg, "system dns", "secondary")
	var present []*ConfigRecord
	if p != nil && len(p.Values) > 0 {
		present = append(present, p)
	}
	if s != nil && len(s.Values) > 0 {
		present = append(present, s)
	}
	if len(present) == 0 {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "fos.dns.no_server",
			Evidence: []Evidence{
				Absent("ev.no_directive", "system dns", map[string]any{"what": "set primary <ip>"}),
			},
		}
	}
	if len(present) < 2 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "fos.dns.single",
			Evidence: []Evidence{fgtEv1(present[0], "system dns")},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.dns.ok"}
}

func CheckFortiOSIntrazoneDeny(cfg ParsedConfig) RuleOutcome {
	zones := SectionEntries(cfg, "system zone")
	if len(zones) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.intrazone.no_zones"}
	}
	var names []string
	for n := range zones {
		names = append(names, n)
	}
	sort.Strings(names)

	var ev []Evidence
	for _, name := range names {
		var rec *ConfigRecord
		for _, r := range zones[name] {
			if r.Key == "intrazone" {
				rec = &r
				break
			}
		}
		if rec == nil {
			ev = append(ev, Absent("ev.no_directive", fgtCtx("system zone", name), map[string]any{"what": "set intrazone deny"}))
		} else if len(rec.Values) == 0 || strings.ToLower(rec.Values[0]) != "deny" {
			ev = append(ev, fgtEv1(rec, "system zone", name))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.intrazone.allowed",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.intrazone.ok"}
}

func CheckFortiOSLoginBanners(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system global") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.banners.no_section"}
	}
	var ev []Evidence
	for _, key := range []string{"pre-login-banner", "post-login-banner"} {
		rec := Setting(cfg, "system global", key)
		if rec == nil {
			ev = append(ev, Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": fmt.Sprintf("set %s enable", key)}))
		} else if len(rec.Values) == 0 || strings.ToLower(rec.Values[0]) != "enable" {
			ev = append(ev, fgtEv1(rec, "system global"))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.banners.missing",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.banners.ok"}
}

func CheckFortiOSTimezone(cfg ParsedConfig) RuleOutcome {
	rec := Setting(cfg, "system global", "timezone")
	if rec == nil {
		if !SectionPresent(cfg, "system global") {
			return RuleOutcome{Status: StatusUnknown, Message: "fos.timezone.no_section"}
		}
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.timezone.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": "set timezone <id>"}),
			},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.timezone.ok"}
}

func CheckFortiOSNTP(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system ntp") {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "fos.ntp.no_section",
			Evidence: []Evidence{
				Absent("ev.no_block", "system ntp", map[string]any{"what": "config system ntp"}),
			},
		}
	}
	var ev []Evidence
	sync := Setting(cfg, "system ntp", "ntpsync")
	if sync == nil || len(sync.Values) == 0 || strings.ToLower(sync.Values[0]) != "enable" {
		if sync != nil {
			ev = append(ev, fgtEv1(sync, "system ntp"))
		} else {
			ev = append(ev, Absent("ev.no_directive", "system ntp", map[string]any{"what": "set ntpsync enable"}))
		}
	}
	servers := make(map[string]bool)
	for _, r := range RecordsUnder(cfg, "system ntp", "ntpserver") {
		if len(r.Path) > 2 {
			servers[r.Path[2]] = true
		}
	}
	ntpType := Setting(cfg, "system ntp", "type")
	isCustom := (ntpType != nil && len(ntpType.Values) > 0 && strings.ToLower(ntpType.Values[0]) == "custom")
	if isCustom && len(servers) == 0 {
		ev = append(ev, Absent("ev.ntp_custom_without_server", "system ntp", nil))
	}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "fos.ntp.not_syncing", Evidence: ev}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "fos.ntp.ok",
		Params:  map[string]any{"count": len(servers)},
	}
}

func CheckFortiOSHostname(cfg ParsedConfig) RuleOutcome {
	rec := Setting(cfg, "system global", "hostname")
	if rec == nil {
		if !SectionPresent(cfg, "system global") {
			return RuleOutcome{Status: StatusUnknown, Message: "fos.hostname.no_section"}
		}
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.hostname.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": "set hostname <nome>"}),
			},
		}
	}
	name := ""
	if len(rec.Values) > 0 {
		name = strings.TrimSpace(rec.Values[0])
	}
	low := strings.ToLower(name)
	if name == "" || strings.HasPrefix(low, "fortigate") || strings.HasPrefix(low, "fgt") {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.hostname.factory",
			Evidence: []Evidence{fgtEv1(rec, "system global")},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.hostname.ok"}
}

func CheckFortiOSAutoInstall(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system auto-install") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.auto_install.no_section"}
	}
	var ev []Evidence
	for _, key := range []string{"auto-install-config", "auto-install-image"} {
		rec := Setting(cfg, "system auto-install", key)
		if rec != nil && len(rec.Values) > 0 && strings.ToLower(rec.Values[0]) == "enable" {
			ev = append(ev, fgtEv1(rec, "system auto-install"))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{Status: StatusFail, Message: "fos.auto_install.enabled", Evidence: ev}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.auto_install.ok"}
}

func CheckFortiOSStaticKeyCiphers(cfg ParsedConfig) RuleOutcome {
	return fgtFlag(cfg, "system global", "ssl-static-key-ciphers", "disable", "fos.static_ciphers", StatusWarn, StatusFail)
}

func CheckFortiOSAdminHttpsRedirect(cfg ParsedConfig) RuleOutcome {
	return fgtFlag(cfg, "system global", "admin-https-redirect", "enable", "fos.https_redirect", StatusWarn, StatusFail)
}

func CheckFortiOSCPULogThreshold(cfg ParsedConfig) RuleOutcome {
	return fgtFlag(cfg, "system global", "log-single-cpu-high", "enable", "fos.cpu_log", StatusWarn, StatusFail)
}

func CheckFortiOSGUIHostnameDisplay(cfg ParsedConfig) RuleOutcome {
	return fgtFlag(cfg, "system global", "gui-display-hostname", "disable", "fos.gui_hostname", StatusWarn, StatusFail)
}

func CheckFortiOSPasswordPolicyStrength(cfg ParsedConfig) RuleOutcome {
	sec := "system password-policy"
	if !SectionPresent(cfg, sec) {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "fos.pwpolicy.no_section",
			Evidence: []Evidence{
				Absent("ev.no_block", sec, map[string]any{"what": "config system password-policy"}),
			},
		}
	}
	var ev []Evidence
	length := Setting(cfg, sec, "minimum-length")
	if length == nil {
		ev = append(ev, Absent("ev.no_directive", fgtCtx(sec), map[string]any{"what": fmt.Sprintf("set minimum-length %d", minPasswordLength)}))
	} else {
		val := fgtIntValue(length)
		if val == nil || *val < minPasswordLength {
			ev = append(ev, fgtEv1(length, sec))
		}
	}
	for _, key := range []string{"min-lower-case-letter", "min-upper-case-letter", "min-non-alphanumeric", "min-number"} {
		rec := Setting(cfg, sec, key)
		val := fgtIntValue(rec)
		if val == nil || *val < 1 {
			if rec != nil {
				ev = append(ev, fgtEv1(rec, sec))
			} else {
				ev = append(ev, Absent("ev.no_directive", fgtCtx(sec), map[string]any{"what": fmt.Sprintf("set %s 1", key)}))
			}
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.pwpolicy.weak",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev), "minlen": minPasswordLength},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "fos.pwpolicy.ok",
		Params:  map[string]any{"minlen": minPasswordLength},
	}
}

func CheckFortiOSAdminLockout(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system global") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.lockout.no_section"}
	}
	var ev []Evidence
	thr := Setting(cfg, "system global", "admin-lockout-threshold")
	if thr == nil {
		ev = append(ev, Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": fmt.Sprintf("set admin-lockout-threshold %d", maxLockoutThreshold)}))
	} else {
		val := fgtIntValue(thr)
		if val == nil || *val > maxLockoutThreshold {
			ev = append(ev, fgtEv1(thr, "system global"))
		}
	}
	dur := Setting(cfg, "system global", "admin-lockout-duration")
	if dur == nil {
		ev = append(ev, Absent("ev.no_directive", fgtCtx("system global"), map[string]any{"what": fmt.Sprintf("set admin-lockout-duration %d", minLockoutDuration)}))
	} else {
		val := fgtIntValue(dur)
		if val == nil || *val < minLockoutDuration {
			ev = append(ev, fgtEv1(dur, "system global"))
		}
	}
	params := map[string]any{"threshold": maxLockoutThreshold, "duration": minLockoutDuration}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.lockout.weak",
			Evidence: ev,
			Params:   params,
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "fos.lockout.ok",
		Params:  params,
	}
}

func CheckFortiOSSNMPV3Only(cfg ParsedConfig) RuleOutcome {
	hasCommunity := SectionPresent(cfg, "system snmp community")
	hasUser := SectionPresent(cfg, "system snmp user")
	if !hasCommunity && !hasUser {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.snmpv3.no_snmp"}
	}
	communities := SectionEntries(cfg, "system snmp community")
	var names []string
	for n := range communities {
		names = append(names, n)
	}
	sort.Strings(names)

	var ev []Evidence
	for _, name := range names {
		recs := communities[name]
		var status *ConfigRecord
		for _, r := range recs {
			if r.Key == "status" {
				status = &r
				break
			}
		}
		if status != nil && len(status.Values) > 0 && strings.ToLower(status.Values[0]) == "disable" {
			continue
		}
		line := 0
		if len(recs) > 0 {
			line = recs[0].Line
		}
		ev = append(ev, Evidence{
			Line:    line,
			Text:    "",
			Context: fgtCtx("system snmp community", name),
			Message: "ev.snmp_v1v2c_active",
		})
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.snmpv3.v1v2c",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	if !hasUser {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.snmpv3.no_user",
			Evidence: []Evidence{
				Absent("ev.no_block", "system snmp user", map[string]any{"what": "config system snmp user"}),
			},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.snmpv3.ok"}
}

func CheckFortiOSAdminPortsChanged(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system global") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.admin_port.no_section"}
	}
	var ev []Evidence
	defaults := map[string]int{
		"admin-sport":    443,
		"admin-ssh-port": 22,
	}
	for _, key := range []string{"admin-sport", "admin-ssh-port"} {
		defVal := defaults[key]
		rec := Setting(cfg, "system global", key)
		if rec == nil {
			ev = append(ev, Absent("ev.not_set_default_value", fgtCtx("system global"), map[string]any{"what": key, "value": defVal}))
		} else {
			val := fgtIntValue(rec)
			if val != nil && *val == defVal {
				ev = append(ev, fgtEv1(rec, "system global"))
			}
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "fos.admin_port.default",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.admin_port.ok"}
}

func CheckFortiOSLocalInPolicy(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "firewall local-in-policy") {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.local_in.no_section",
			Evidence: []Evidence{
				Absent("ev.no_block", "firewall local-in-policy", map[string]any{"what": "config firewall local-in-policy"}),
			},
		}
	}
	entries := SectionEntries(cfg, "firewall local-in-policy")
	if len(entries) == 0 {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.local_in.empty",
			Evidence: []Evidence{
				Absent("ev.block_empty", "firewall local-in-policy", nil),
			},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "fos.local_in.ok",
		Params:  map[string]any{"count": len(entries)},
	}
}

func CheckFortiOSHAConfigured(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "system ha") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.ha.no_section"}
	}
	mode := Setting(cfg, "system ha", "mode")
	if mode == nil || len(mode.Values) == 0 || strings.ToLower(mode.Values[0]) == "standalone" || mode.Values[0] == "" {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.ha.standalone"}
	}
	monitor := Setting(cfg, "system ha", "monitor")
	if monitor == nil || len(monitor.Values) == 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.ha.no_monitor",
			Evidence: []Evidence{fgtEv1(mode, "system ha")},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "fos.ha.ok",
		Params:  map[string]any{"mode": mode.Values[0], "count": len(monitor.Values)},
	}
}

func CheckFortiOSPolicyLogging(cfg ParsedConfig) RuleOutcome {
	policies := SectionEntries(cfg, "firewall policy")
	if len(policies) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_section"}
	}
	accepted := acceptPolicies(cfg)
	var ev []Evidence
	for _, item := range accepted {
		var rec *ConfigRecord
		for _, r := range item.Recs {
			if r.Key == "logtraffic" {
				rec = &r
				break
			}
		}
		if rec == nil {
			ev = append(ev, Absent("ev.no_directive", fgtCtx("firewall policy", item.Pid), map[string]any{"what": "set logtraffic all"}))
		} else if len(rec.Values) > 0 && strings.ToLower(rec.Values[0]) == "disable" {
			ev = append(ev, fgtEv1(rec, "firewall policy", item.Pid))
		}
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.policy_log.missing",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.policy_log.ok"}
}

func CheckFortiOSPolicySecurityProfiles(cfg ParsedConfig) RuleOutcome {
	policies := SectionEntries(cfg, "firewall policy")
	if len(policies) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_section"}
	}
	wan := WanInterfaces(cfg)
	if len(wan) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_wan"}
	}
	accepted := acceptPolicies(cfg)
	var ev []Evidence
	for _, item := range accepted {
		vals := policyValues(item.Recs)
		toWan := false
		for _, di := range vals["dstintf"] {
			if wan[di] {
				toWan = true
				break
			}
		}
		if !toWan {
			continue
		}
		hasProfile := false
		for _, sp := range securityProfiles {
			if _, ok := vals[sp]; ok {
				hasProfile = true
				break
			}
		}
		if hasProfile {
			continue
		}
		line, raw := policyLine(item.Recs, "action")
		ev = append(ev, Evidence{
			Line:    line,
			Text:    raw,
			Context: fgtCtx("firewall policy", item.Pid),
		})
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "fos.profiles.missing",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.profiles.ok"}
}

func CheckFortiOSPolicyComments(cfg ParsedConfig) RuleOutcome {
	policies := SectionEntries(cfg, "firewall policy")
	if len(policies) == 0 {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.policy.no_section"}
	}
	var pids []string
	for pid := range policies {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool {
		if len(pids[i]) != len(pids[j]) {
			return len(pids[i]) < len(pids[j])
		}
		return pids[i] < pids[j]
	})
	var ev []Evidence
	for _, pid := range pids {
		recs := policies[pid]
		hasComment := false
		for _, r := range recs {
			if (r.Key == "comments" || r.Key == "comment") && len(r.Values) > 0 {
				hasComment = true
				break
			}
		}
		if hasComment {
			continue
		}
		line, raw := policyLine(recs, "action")
		ev = append(ev, Evidence{
			Line:    line,
			Text:    raw,
			Context: fgtCtx("firewall policy", pid),
		})
	}
	if len(ev) > 0 {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "fos.comments.missing",
			Evidence: ev,
			Params:   map[string]any{"count": len(ev)},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.comments.ok"}
}

func CheckFortiOSSSLVPNTLS(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "vpn ssl settings") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.sslvpn.no_section"}
	}
	rec := Setting(cfg, "vpn ssl settings", "ssl-min-proto-ver")
	if rec == nil {
		rec = Setting(cfg, "vpn ssl settings", "ssl-min-proto-version")
	}
	if rec == nil {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.sslvpn_tls.not_set",
			Evidence: []Evidence{
				Absent("ev.no_directive", "vpn ssl settings", map[string]any{"what": "set ssl-min-proto-ver tls1-2"}),
			},
		}
	}
	val := ""
	if len(rec.Values) > 0 {
		val = strings.ToLower(rec.Values[0])
	}
	if val == "tls1-2" || val == "tls1-3" || val == "tlsv1-2" || val == "tlsv1-3" {
		return RuleOutcome{Status: StatusPass, Message: "fos.sslvpn_tls.ok"}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "fos.sslvpn_tls.weak",
		Evidence: []Evidence{fgtEv1(rec, "vpn ssl settings")},
		Params:   map[string]any{"version": val},
	}
}

func CheckFortiOSSSLVPNSourceRestriction(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "vpn ssl settings") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.sslvpn.no_section"}
	}
	rec := Setting(cfg, "vpn ssl settings", "source-address")
	if rec == nil || len(rec.Values) == 0 {
		return RuleOutcome{
			Status:  StatusWarn,
			Message: "fos.sslvpn_src.unrestricted",
			Evidence: []Evidence{
				Absent("ev.no_directive", "vpn ssl settings", map[string]any{"what": "set source-address <gruppo>"}),
			},
		}
	}
	hasAny := false
	for _, v := range rec.Values {
		if anyAddr[strings.ToLower(v)] {
			hasAny = true
			break
		}
	}
	if hasAny {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "fos.sslvpn_src.any",
			Evidence: []Evidence{fgtEv1(rec, "vpn ssl settings")},
		}
	}
	return RuleOutcome{Status: StatusPass, Message: "fos.sslvpn_src.ok"}
}

func CheckFortiOSSyslogEncrypted(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "log syslogd setting") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.syslog_enc.no_syslog"}
	}
	status := Setting(cfg, "log syslogd setting", "status")
	if status == nil || len(status.Values) == 0 || strings.ToLower(status.Values[0]) != "enable" {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.syslog_enc.disabled"}
	}
	rec := Setting(cfg, "log syslogd setting", "enc-algorithm")
	if rec != nil && len(rec.Values) > 0 {
		alg := strings.ToLower(rec.Values[0])
		if alg == "high" || alg == "high-medium" || alg == "low" {
			return RuleOutcome{
				Status:  StatusPass,
				Message: "fos.syslog_enc.ok",
				Params:  map[string]any{"algorithm": rec.Values[0]},
			}
		}
	}
	var ev []Evidence
	if rec != nil {
		ev = append(ev, fgtEv1(rec, "log syslogd setting"))
	} else {
		ev = append(ev, Absent("ev.no_directive", "log syslogd setting", map[string]any{"what": "set enc-algorithm high"}))
	}
	return RuleOutcome{
		Status:   StatusWarn,
		Message:  "fos.syslog_enc.plaintext",
		Evidence: ev,
	}
}

func CheckFortiOSEventLogging(cfg ParsedConfig) RuleOutcome {
	return fgtFlag(cfg, "log eventfilter", "event", "enable", "fos.event_log", StatusWarn, StatusFail)
}

func CheckFortiOSLogLocalDisk(cfg ParsedConfig) RuleOutcome {
	if !SectionPresent(cfg, "log disk setting") {
		return RuleOutcome{Status: StatusUnknown, Message: "fos.log_disk.no_section"}
	}
	status := Setting(cfg, "log disk setting", "status")
	if status != nil && len(status.Values) > 0 && strings.ToLower(status.Values[0]) == "enable" {
		return RuleOutcome{Status: StatusPass, Message: "fos.log_disk.ok"}
	}
	var ev []Evidence
	if status != nil {
		ev = append(ev, fgtEv1(status, "log disk setting"))
	} else {
		ev = append(ev, Absent("ev.no_directive", "log disk setting", map[string]any{"what": "set status enable"}))
	}
	return RuleOutcome{
		Status:   StatusWarn,
		Message:  "fos.log_disk.disabled",
		Evidence: ev,
	}
}
