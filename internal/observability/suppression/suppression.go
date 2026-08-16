// Package suppression: gestione delle soppressioni pianificate e stati attesi.
// Porta di observability/suppression.py.
package suppression

import (
	"fmt"
	"time"
)

const AnyInterface = "*"

type Rule struct {
	Tenant     string `json:"tenant"`
	EntityKey  string `json:"entity_key"`
	DeviceIP   string `json:"device_ip,omitempty"`
	Interface  string `json:"interface,omitempty"`
	FromTS     *int64 `json:"from_ts,omitempty"`
	ToTS       *int64 `json:"to_ts,omitempty"`
	Note       string `json:"note,omitempty"`
	By         string `json:"by,omitempty"`
	CreatedTS  int64  `json:"created_ts,omitempty"`
	Key        string `json:"key,omitempty"`
	Expired    bool   `json:"expired,omitempty"`
	Suppressed bool   `json:"suppressed,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// Key genera la chiave deterministica.
func Key(tenant, entityKey, iface string) string {
	if iface == "" {
		iface = AnyInterface
	}
	return fmt.Sprintf("%s|%s|%s", tenant, entityKey, iface)
}

func covers(rule Rule, iface string) bool {
	target := rule.Interface
	if target == "" || target == AnyInterface {
		return true
	}
	return target == iface
}

func inWindow(rule Rule, atTS int64) bool {
	if rule.FromTS != nil && atTS < *rule.FromTS {
		return false
	}
	if rule.ToTS != nil && atTS > *rule.ToTS {
		return false
	}
	return true
}

// Active verifica se esiste una soppressione attiva per il target al timestamp indicato.
func Active(rules map[string]Rule, tenant, entityKey, iface string, atTS int64) *Rule {
	if entityKey == "" {
		return nil
	}
	for _, r := range rules {
		if r.Tenant != tenant || r.EntityKey != entityKey {
			continue
		}
		if covers(r, iface) && inWindow(r, atTS) {
			copyRule := r
			return &copyRule
		}
	}
	return nil
}

// Expired verifica se una finestra temporale  passata.
func Expired(rule Rule, now int64) bool {
	if now == 0 {
		now = time.Now().Unix()
	}
	return rule.ToTS != nil && *rule.ToTS < now
}
