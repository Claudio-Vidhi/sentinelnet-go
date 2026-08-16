// Package portaction: azioni sicure sulle porte di accesso di switch e apparati.
// Porta di services/port_action.py.
package portaction

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Claudio-Vidhi/sentinelnet-go/internal/collect"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/driver"
	"github.com/Claudio-Vidhi/sentinelnet-go/internal/store"
)

var ifaceRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9/.:\-]{0,62}$`)

type BounceCommands struct {
	Down []string
	Up   []string
}

var bounceCommandMap = map[string]BounceCommands{
	"cisco_ios": {
		Down: []string{"interface %s", "shutdown"},
		Up:   []string{"interface %s", "no shutdown"},
	},
	"cisco_xe": {
		Down: []string{"interface %s", "shutdown"},
		Up:   []string{"interface %s", "no shutdown"},
	},
	"cisco_s300": {
		Down: []string{"interface %s", "shutdown"},
		Up:   []string{"interface %s", "no shutdown"},
	},
	"cisco_9800": {
		Down: []string{"interface %s", "shutdown"},
		Up:   []string{"interface %s", "no shutdown"},
	},
	"hp_procurve": {
		Down: []string{"interface %s", "disable"},
		Up:   []string{"interface %s", "enable"},
	},
	"aruba_os": {
		Down: []string{"interface %s", "disable"},
		Up:   []string{"interface %s", "enable"},
	},
}

// BuildCommands costruisce le sequenze di comandi sicure per l'interfaccia.
func BuildCommands(driverType, iface string) (down, up []string, err error) {
	if !ifaceRe.MatchString(iface) {
		return nil, nil, fmt.Errorf("nome di interfaccia non valido: '%s'", iface)
	}

	normDriver := strings.ToLower(driverType)
	cmds, ok := bounceCommandMap[normDriver]
	if !ok {
		if strings.HasPrefix(normDriver, "cisco") {
			cmds = bounceCommandMap["cisco_ios"]
		} else {
			return nil, nil, fmt.Errorf("bounce non supportato per '%s': sintassi vendor non verificata", driverType)
		}
	}

	formatCmds := func(templates []string) []string {
		var out []string
		for _, c := range templates {
			if strings.Contains(c, "%s") {
				out = append(out, fmt.Sprintf(c, iface))
			} else {
				out = append(out, c)
			}
		}
		return out
	}

	return formatCmds(cmds.Down), formatCmds(cmds.Up), nil
}

type ClientMapLookup interface {
	ClientMap(mac, ip, sourceIP string, tenants []string, limit int) ([]*store.ClientMapRow, error)
}

// VerifyPort controlla che il client MAC si trovi effettivamente sullo switch e porta indicati.
func VerifyPort(lookup ClientMapLookup, clientMAC, switchIP, iface string, allowedTenants []string) (bool, string) {
	if lookup == nil {
		return true, ""
	}
	rows, err := lookup.ClientMap(clientMAC, "", "", allowedTenants, 5)
	if err != nil || len(rows) == 0 {
		return false, fmt.Sprintf("Client MAC '%s' non trovato nella mappa di accesso.", clientMAC)
	}

	match := false
	for _, r := range rows {
		sw := r.SwitchName
		if sw == "" {
			sw = r.SwitchIP
		}
		if (r.SwitchIP == switchIP || sw == switchIP) && strings.EqualFold(r.SwitchPort, iface) {
			match = true
			break
		}
	}

	if !match {
		return false, fmt.Sprintf("Il client '%s' non risulta attaccato alla porta '%s' dello switch '%s'.", clientMAC, iface, switchIP)
	}
	return true, ""
}

// SetAdminState spegne o riaccende un'interfaccia e ritorna l'esito.
func SetAdminState(ctx context.Context, host string, creds collect.Credentials, vendor, iface string, up bool) (map[string]any, error) {
	driverType := driver.DriverName(vendor, "")
	downCmds, upCmds, err := BuildCommands(driverType, iface)
	if err != nil {
		return nil, err
	}

	targetCmds := downCmds
	if up {
		targetCmds = upCmds
	}

	sess, err := collect.Dial(ctx, host, creds)
	if err != nil {
		return nil, fmt.Errorf("connessione fallita a %s: %w", host, err)
	}
	defer sess.Close()

	output := sess.RunConfig(targetCmds)
	return map[string]any{
		"interface": iface,
		"commands":  targetCmds,
		"output":    output,
		"admin_up":  up,
	}, nil
}

// Bounce spegne e riaccende un'interfaccia con una pausa.
func Bounce(ctx context.Context, host string, creds collect.Credentials, vendor, iface string, waitSec float64) (map[string]any, error) {
	driverType := driver.DriverName(vendor, "")
	downCmds, upCmds, err := BuildCommands(driverType, iface)
	if err != nil {
		return nil, err
	}

	sess, err := collect.Dial(ctx, host, creds)
	if err != nil {
		return nil, fmt.Errorf("connessione fallita a %s: %w", host, err)
	}
	defer sess.Close()

	out := map[string]any{
		"interface": iface,
		"commands": map[string]any{
			"down": downCmds,
			"up":   upCmds,
		},
	}

	downOut := sess.RunConfig(downCmds)
	out["down_output"] = downOut
	out["down_ok"] = true

	if waitSec < 1.0 {
		waitSec = 2.0
	}
	time.Sleep(time.Duration(waitSec * float64(time.Second)))

	upOut := sess.RunConfig(upCmds)
	out["up_output"] = upOut
	out["up_ok"] = true

	return out, nil
}
