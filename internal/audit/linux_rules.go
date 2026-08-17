package audit

import (
	"strconv"
	"strings"
)

const (
	sshdConfigPath = "/etc/ssh/sshd_config"
	loginDefsPath  = "/etc/login.defs"
	sysctlConfPath = "/etc/sysctl.conf"
	fstabPath      = "/etc/fstab"

	maxAuthTries    = 4
	maxLoginGraceS  = 60
	maxPassMaxDays  = 365
	minPassMinDays  = 1
	minPassWarnAge  = 7
)

var (
	strongHashes = map[string]bool{"sha512": true, "yescrypt": true}
	logLevels    = map[string]bool{"info": true, "verbose": true}
)

func lnxEv(l LinuxLine, note ...string) Evidence {
	ctx := ""
	if len(note) > 0 {
		ctx = note[0]
	}
	return Evidence{
		Line:    l.Line,
		Text:    l.Text,
		Context: ctx,
	}
}

func lnxGuard(cfg LinuxConfig) *RuleOutcome {
	if cfg.IsEmpty() {
		return &RuleOutcome{Status: StatusUnknown, Message: "lnx.empty"}
	}
	return nil
}

func lnxIntOf(l *LinuxLine, index int) *int {
	if l == nil || len(l.Words) <= index {
		return nil
	}
	v, err := strconv.Atoi(l.Words[index])
	if err != nil {
		return nil
	}
	return &v
}

func sshdDirective(cfg LinuxConfig, keyword string) (*LinuxLine, string) {
	effective := cfg.Files[SshdEffective]
	hit := LinuxFirstDirective(effective, keyword)
	if hit != nil {
		return hit, "set"
	}
	if !LinuxHasFile(cfg, sshdConfigPath) {
		return nil, "unknown"
	}
	lines := cfg.Files[sshdConfigPath]
	hit = LinuxFirstDirective(lines, keyword)
	if hit != nil {
		return hit, "set"
	}
	if len(LinuxDirectives(lines, "include")) > 0 {
		return nil, "unknown"
	}
	return nil, "default"
}

func sshdFlag(cfg LinuxConfig, keyword, wanted, okKey, badKey, defaultValue string) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	line, state := sshdDirective(cfg, keyword)
	if state == "unknown" {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.sshd.not_assessable",
			Params:  map[string]any{"what": keyword},
		}
	}
	if state == "default" {
		if defaultValue == wanted {
			return RuleOutcome{
				Status:  StatusPass,
				Message: okKey,
				Params:  map[string]any{"value": defaultValue},
			}
		}
		return RuleOutcome{
			Status:  StatusFail,
			Message: badKey,
			Evidence: []Evidence{
				Absent("ev.not_set_default_value", sshdConfigPath, map[string]any{"what": keyword, "value": defaultValue}),
			},
			Params: map[string]any{"value": defaultValue},
		}
	}
	value := ""
	if len(line.Words) > 1 {
		value = line.Words[1]
	}
	if value == wanted {
		return RuleOutcome{
			Status:  StatusPass,
			Message: okKey,
			Params:  map[string]any{"value": value},
		}
	}
	valDisp := value
	if valDisp == "" {
		valDisp = "-"
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  badKey,
		Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		Params:   map[string]any{"value": valDisp},
	}
}

func CheckLinuxSSHD_PermitRootLogin(cfg LinuxConfig) RuleOutcome {
	return sshdFlag(cfg, "permitrootlogin", "no", "lnx.sshd_root.ok", "lnx.sshd_root.allowed", "prohibit-password")
}

func CheckLinuxSSHD_PermitEmptyPasswords(cfg LinuxConfig) RuleOutcome {
	return sshdFlag(cfg, "permitemptypasswords", "no", "lnx.sshd_empty.ok", "lnx.sshd_empty.allowed", "no")
}

func CheckLinuxSSHD_HostbasedAuth(cfg LinuxConfig) RuleOutcome {
	return sshdFlag(cfg, "hostbasedauthentication", "no", "lnx.sshd_hostbased.ok", "lnx.sshd_hostbased.enabled", "no")
}

func CheckLinuxSSHD_IgnoreRhosts(cfg LinuxConfig) RuleOutcome {
	return sshdFlag(cfg, "ignorerhosts", "yes", "lnx.sshd_rhosts.ok", "lnx.sshd_rhosts.honored", "yes")
}

func CheckLinuxSSHD_DisableForwarding(cfg LinuxConfig) RuleOutcome {
	return sshdFlag(cfg, "disableforwarding", "yes", "lnx.sshd_forwarding.ok", "lnx.sshd_forwarding.allowed", "no")
}

func CheckLinuxSSHD_MaxAuthTries(cfg LinuxConfig) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	line, state := sshdDirective(cfg, "maxauthtries")
	if state == "unknown" {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.sshd.not_assessable",
			Params:  map[string]any{"what": "MaxAuthTries"},
		}
	}
	if state == "default" {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "lnx.sshd_authtries.high",
			Evidence: []Evidence{
				Absent("ev.not_set_default_value", sshdConfigPath, map[string]any{"what": "MaxAuthTries", "value": 6}),
			},
			Params: map[string]any{"value": 6, "max": maxAuthTries},
		}
	}
	val := lnxIntOf(line, 1)
	if val == nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "lnx.sshd_authtries.unreadable",
			Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		}
	}
	if *val <= maxAuthTries {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "lnx.sshd_authtries.ok",
			Params:  map[string]any{"value": *val},
		}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "lnx.sshd_authtries.high",
		Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		Params:   map[string]any{"value": *val, "max": maxAuthTries},
	}
}

func CheckLinuxSSHD_LoginGraceTime(cfg LinuxConfig) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	line, state := sshdDirective(cfg, "logingracetime")
	if state == "unknown" {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.sshd.not_assessable",
			Params:  map[string]any{"what": "LoginGraceTime"},
		}
	}
	if state == "default" {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "lnx.sshd_grace.high",
			Evidence: []Evidence{
				Absent("ev.not_set_default_value", sshdConfigPath, map[string]any{"what": "LoginGraceTime", "value": 120}),
			},
			Params: map[string]any{"value": 120, "max": maxLoginGraceS},
		}
	}
	val := lnxIntOf(line, 1)
	if val == nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "lnx.sshd_grace.unreadable",
			Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		}
	}
	if *val >= 1 && *val <= maxLoginGraceS {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "lnx.sshd_grace.ok",
			Params:  map[string]any{"value": *val},
		}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "lnx.sshd_grace.high",
		Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		Params:   map[string]any{"value": *val, "max": maxLoginGraceS},
	}
}

func CheckLinuxSSHD_ClientAlive(cfg LinuxConfig) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	var intervalVal, countVal *int
	var intervalLine, countLine *LinuxLine

	iLine, iState := sshdDirective(cfg, "clientaliveinterval")
	if iState == "unknown" {
		return RuleOutcome{Status: StatusUnknown, Message: "lnx.sshd.not_assessable", Params: map[string]any{"what": "ClientAlive*"}}
	}
	if iState == "default" {
		zero := 0
		intervalVal = &zero
	} else {
		intervalVal = lnxIntOf(iLine, 1)
		intervalLine = iLine
	}

	cLine, cState := sshdDirective(cfg, "clientalivecountmax")
	if cState == "unknown" {
		return RuleOutcome{Status: StatusUnknown, Message: "lnx.sshd.not_assessable", Params: map[string]any{"what": "ClientAlive*"}}
	}
	if cState == "default" {
		three := 3
		countVal = &three
	} else {
		countVal = lnxIntOf(cLine, 1)
		countLine = cLine
	}

	intOk := intervalVal != nil && *intervalVal > 0
	cntOk := countVal != nil && *countVal > 0

	if !intOk || !cntOk {
		var ev []Evidence
		if intervalLine != nil && (intervalVal == nil || *intervalVal == 0) {
			ev = append(ev, lnxEv(*intervalLine, sshdConfigPath))
		}
		if countLine != nil && (countVal == nil || *countVal == 0) {
			ev = append(ev, lnxEv(*countLine, sshdConfigPath))
		}
		if len(ev) == 0 {
			ev = append(ev, Absent("ev.not_set_default_value", sshdConfigPath, map[string]any{"what": "ClientAliveInterval", "value": 0}))
		}
		iValDisp, cValDisp := 0, 0
		if intervalVal != nil {
			iValDisp = *intervalVal
		}
		if countVal != nil {
			cValDisp = *countVal
		}
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "lnx.sshd_alive.disabled",
			Evidence: ev,
			Params:   map[string]any{"interval": iValDisp, "count": cValDisp},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "lnx.sshd_alive.ok",
		Params:  map[string]any{"interval": *intervalVal, "count": *countVal},
	}
}

func CheckLinuxSSHD_LogLevel(cfg LinuxConfig) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	line, state := sshdDirective(cfg, "loglevel")
	if state == "unknown" {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.sshd.not_assessable",
			Params:  map[string]any{"what": "LogLevel"},
		}
	}
	if state == "default" {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "lnx.sshd_loglevel.ok",
			Params:  map[string]any{"value": "INFO"},
		}
	}
	val := ""
	if len(line.Words) > 1 {
		val = line.Words[1]
	}
	if logLevels[val] {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "lnx.sshd_loglevel.ok",
			Params:  map[string]any{"value": val},
		}
	}
	valDisp := val
	if valDisp == "" {
		valDisp = "-"
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "lnx.sshd_loglevel.weak",
		Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		Params:   map[string]any{"value": valDisp},
	}
}

func CheckLinuxSSHD_Banner(cfg LinuxConfig) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	line, state := sshdDirective(cfg, "banner")
	if state == "unknown" {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.sshd.not_assessable",
			Params:  map[string]any{"what": "Banner"},
		}
	}
	if state == "default" {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "lnx.sshd_banner.absent",
			Evidence: []Evidence{Absent("ev.no_directive", sshdConfigPath, map[string]any{"what": "Banner"})},
		}
	}
	val := ""
	if len(line.Words) > 1 {
		val = line.Words[1]
	}
	if val == "" || val == "none" {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  "lnx.sshd_banner.absent",
			Evidence: []Evidence{lnxEv(*line, sshdConfigPath)},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: "lnx.sshd_banner.ok",
		Params:  map[string]any{"value": val},
	}
}

func loginDefsInt(cfg LinuxConfig, keyword string) (*int, *LinuxLine, string) {
	if !LinuxHasFile(cfg, loginDefsPath) {
		return nil, nil, "no_file"
	}
	line := LinuxLastDirective(cfg.Files[loginDefsPath], keyword)
	if line == nil {
		return nil, nil, "absent"
	}
	return lnxIntOf(line, 1), line, "set"
}

func passPolicy(cfg LinuxConfig, keyword, okKey, badKey string, limit int, atMost bool) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	val, line, state := loginDefsInt(cfg, keyword)
	if state == "no_file" {
		return RuleOutcome{Status: StatusUnknown, Message: "lnx.login_defs.absent"}
	}
	if state == "absent" {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "lnx.pass_policy.undeclared",
			Evidence: []Evidence{
				Absent("ev.no_directive", loginDefsPath, map[string]any{"what": keyword}),
			},
			Params: map[string]any{"what": keyword},
		}
	}
	if val == nil {
		return RuleOutcome{
			Status:   StatusWarn,
			Message:  "lnx.pass_policy.unreadable",
			Evidence: []Evidence{lnxEv(*line, loginDefsPath)},
			Params:   map[string]any{"what": keyword},
		}
	}
	ok := false
	if atMost {
		ok = (*val > 0 && *val <= limit)
	} else {
		ok = (*val >= limit)
	}
	if ok {
		return RuleOutcome{
			Status:  StatusPass,
			Message: okKey,
			Params:  map[string]any{"value": *val},
		}
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  badKey,
		Evidence: []Evidence{lnxEv(*line, loginDefsPath)},
		Params:   map[string]any{"value": *val, "limit": limit},
	}
}

func CheckLinuxPassMaxDays(cfg LinuxConfig) RuleOutcome {
	return passPolicy(cfg, "pass_max_days", "lnx.pass_max.ok", "lnx.pass_max.too_long", maxPassMaxDays, true)
}

func CheckLinuxPassMinDays(cfg LinuxConfig) RuleOutcome {
	return passPolicy(cfg, "pass_min_days", "lnx.pass_min.ok", "lnx.pass_min.too_short", minPassMinDays, false)
}

func CheckLinuxPassWarnAge(cfg LinuxConfig) RuleOutcome {
	return passPolicy(cfg, "pass_warn_age", "lnx.pass_warn.ok", "lnx.pass_warn.too_short", minPassWarnAge, false)
}

func CheckLinuxEncryptMethod(cfg LinuxConfig) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	if !LinuxHasFile(cfg, loginDefsPath) {
		return RuleOutcome{Status: StatusUnknown, Message: "lnx.login_defs.absent"}
	}
	line := LinuxLastDirective(cfg.Files[loginDefsPath], "encrypt_method")
	if line == nil {
		return RuleOutcome{
			Status:  StatusFail,
			Message: "lnx.encrypt.undeclared",
			Evidence: []Evidence{
				Absent("ev.no_directive", loginDefsPath, map[string]any{"what": "ENCRYPT_METHOD"}),
			},
		}
	}
	val := ""
	if len(line.Words) > 1 {
		val = line.Words[1]
	}
	if strongHashes[val] {
		return RuleOutcome{
			Status:  StatusPass,
			Message: "lnx.encrypt.ok",
			Params:  map[string]any{"value": strings.ToUpper(val)},
		}
	}
	valDisp := strings.ToUpper(val)
	if valDisp == "" {
		valDisp = "-"
	}
	return RuleOutcome{
		Status:   StatusFail,
		Message:  "lnx.encrypt.weak",
		Evidence: []Evidence{lnxEv(*line, loginDefsPath)},
		Params:   map[string]any{"value": valDisp},
	}
}

func mountOptions(cfg LinuxConfig, mountPoint string, wanted []string, okKey, badKey string) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	if !LinuxHasFile(cfg, fstabPath) {
		return RuleOutcome{Status: StatusUnknown, Message: "lnx.fstab.absent"}
	}
	entry := LinuxFstabEntry(cfg.Files[fstabPath], mountPoint)
	if entry == nil {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.mount.not_separate",
			Params:  map[string]any{"mount": mountPoint},
		}
	}
	opts := LinuxFstabOptions(*entry)
	optsMap := make(map[string]bool)
	for _, o := range opts {
		optsMap[o] = true
	}
	var missing []string
	for _, w := range wanted {
		if !optsMap[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		return RuleOutcome{
			Status:   StatusFail,
			Message:  badKey,
			Evidence: []Evidence{lnxEv(*entry, fstabPath)},
			Params:   map[string]any{"mount": mountPoint, "missing": strings.Join(missing, ", ")},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: okKey,
		Params:  map[string]any{"mount": mountPoint},
	}
}

func CheckLinuxTmpMountOptions(cfg LinuxConfig) RuleOutcome {
	return mountOptions(cfg, "/tmp", []string{"nodev", "nosuid", "noexec"}, "lnx.mount.ok", "lnx.mount.missing_options")
}

func CheckLinuxVarMountOptions(cfg LinuxConfig) RuleOutcome {
	return mountOptions(cfg, "/var", []string{"nodev", "nosuid"}, "lnx.mount.ok", "lnx.mount.missing_options")
}

func sysctlRule(cfg LinuxConfig, keys []string, wanted, okKey, badKey string) RuleOutcome {
	if g := lnxGuard(cfg); g != nil {
		return *g
	}
	if !LinuxHasFile(cfg, sysctlConfPath) {
		return RuleOutcome{Status: StatusUnknown, Message: "lnx.sysctl.absent"}
	}
	lines := cfg.Files[sysctlConfPath]
	var found, wrong []LinuxLine
	for _, key := range keys {
		l := LinuxSysctlValue(lines, key)
		if l == nil {
			continue
		}
		found = append(found, *l)
		parts := strings.SplitN(l.Lower, "=", 2)
		val := ""
		if len(parts) == 2 {
			val = strings.TrimSpace(parts[1])
		}
		if val != wanted {
			wrong = append(wrong, *l)
		}
	}
	if len(wrong) > 0 {
		var ev []Evidence
		for _, w := range wrong {
			ev = append(ev, lnxEv(w, sysctlConfPath))
		}
		return RuleOutcome{
			Status:   StatusFail,
			Message:  badKey,
			Evidence: ev,
			Params:   map[string]any{"count": len(wrong), "value": wanted},
		}
	}
	if len(found) == 0 {
		return RuleOutcome{
			Status:  StatusUnknown,
			Message: "lnx.sysctl.not_declared",
			Params:  map[string]any{"what": keys[0]},
		}
	}
	return RuleOutcome{
		Status:  StatusPass,
		Message: okKey,
		Params:  map[string]any{"count": len(found)},
	}
}

func CheckLinuxIPForward(cfg LinuxConfig) RuleOutcome {
	return sysctlRule(cfg, []string{"net.ipv4.ip_forward"}, "0", "lnx.sysctl_forward.ok", "lnx.sysctl_forward.enabled")
}

func CheckLinuxAcceptRedirects(cfg LinuxConfig) RuleOutcome {
	return sysctlRule(cfg, []string{"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.default.accept_redirects"}, "0", "lnx.sysctl_accept_redirects.ok", "lnx.sysctl_accept_redirects.enabled")
}

func CheckLinuxSendRedirects(cfg LinuxConfig) RuleOutcome {
	return sysctlRule(cfg, []string{"net.ipv4.conf.all.send_redirects", "net.ipv4.conf.default.send_redirects"}, "0", "lnx.sysctl_send_redirects.ok", "lnx.sysctl_send_redirects.enabled")
}

func CheckLinuxSourceRoute(cfg LinuxConfig) RuleOutcome {
	return sysctlRule(cfg, []string{"net.ipv4.conf.all.accept_source_route", "net.ipv4.conf.default.accept_source_route"}, "0", "lnx.sysctl_source_route.ok", "lnx.sysctl_source_route.enabled")
}

func CheckLinuxTCPSyncookies(cfg LinuxConfig) RuleOutcome {
	return sysctlRule(cfg, []string{"net.ipv4.tcp_syncookies"}, "1", "lnx.sysctl_syncookies.ok", "lnx.sysctl_syncookies.disabled")
}

func CheckLinuxLogMartians(cfg LinuxConfig) RuleOutcome {
	return sysctlRule(cfg, []string{"net.ipv4.conf.all.log_martians", "net.ipv4.conf.default.log_martians"}, "1", "lnx.sysctl_martians.ok", "lnx.sysctl_martians.disabled")
}
