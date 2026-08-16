package suppression

import (
	"testing"
)

func TestSuppression(t *testing.T) {
	from := int64(1000)
	to := int64(2000)
	rule := Rule{
		Tenant:    "T1",
		EntityKey: "ip:192.168.1.1",
		Interface: "Gi1/0/1",
		FromTS:    &from,
		ToTS:      &to,
	}

	rules := map[string]Rule{
		Key("T1", "ip:192.168.1.1", "Gi1/0/1"): rule,
	}

	if Active(rules, "T1", "ip:192.168.1.1", "Gi1/0/1", 1500) == nil {
		t.Errorf("expected active suppression at 1500")
	}
	if Active(rules, "T1", "ip:192.168.1.1", "Gi1/0/1", 2500) != nil {
		t.Errorf("expected inactive suppression at 2500")
	}
	if Active(rules, "T1", "ip:192.168.1.1", "Gi1/0/2", 1500) != nil {
		t.Errorf("expected inactive for different interface")
	}
	if !Expired(rule, 3000) {
		t.Errorf("expected expired rule at 3000")
	}
}
