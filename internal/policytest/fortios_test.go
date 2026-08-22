package policytest

import (
	"testing"
)

func TestPolicyFortiOS(t *testing.T) {
	sampleConfig := `
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
        set status up
    next
    edit "port2"
        set ip 198.51.100.1 255.255.255.0
        set status up
    next
end

config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 198.51.100.254
        set device "port2"
    next
end

config firewall address
    edit "INTERNAL_HOST"
        set subnet 192.0.2.50 255.255.255.255
    next
    edit "DMZ_NET"
        set subnet 192.0.2.0 255.255.255.0
    next
    edit "BRANCH_NET"
        set subnet 198.51.100.128 255.255.255.128
    next
end

config firewall addrgrp
    edit "LOCAL_NETWORKS"
        set member "DMZ_NET" "BRANCH_NET"
    next
    edit "NESTED_GROUP"
        set member "LOCAL_NETWORKS" "INTERNAL_HOST"
    next
end

config firewall service custom
    edit "CUSTOM_APP_8443"
        set protocol TCP/UDP/SCTP
        set tcp-portrange 8443
    next
end

config firewall policy
    edit 1
        set name "Disabled Rule"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set status disable
        set service "ALL"
    next
    edit 10
        set name "Allow Web Out"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "NESTED_GROUP"
        set dstaddr "all"
        set action accept
        set service "HTTPS" "HTTP"
        set nat enable
    next
    edit 20
        set name "Allow Custom App"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "INTERNAL_HOST"
        set dstaddr "all"
        set action accept
        set service "CUSTOM_APP_8443"
    next
    edit 30
        set name "Broken Policy"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "UNDEFINED_ADDRESS"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
`
	env := ParseFortiOSConfig(sampleConfig)

	nested, ok := env.Addresses["NESTED_GROUP"]
	if !ok || len(nested) != 3 {
		t.Fatalf("NESTED_GROUP address resolution count = %d, expected 3", len(nested))
	}

	customSvc, ok := env.Services["CUSTOM_APP_8443"]
	if !ok || customSvc.DstPorts == nil || len(customSvc.DstPorts.Intervals) != 1 || customSvc.DstPorts.Intervals[0].Lo != 8443 {
		t.Fatalf("CUSTOM_APP_8443 service resolution mismatch: %v", customSvc)
	}

	// Flow matching policy 10 (HTTPS with NAT)
	flow := Flow{
		SrcIP: "192.0.2.50",
		DstIP: "203.0.113.5",
		Proto: "tcp",
		DPort: intPtr(443),
	}
	trace, err := Evaluate(env, flow)
	if err != nil || trace.Verdict != "PERMIT" || !trace.NATApplied {
		t.Fatalf("Evaluate flow failed: verdict=%s, nat=%v, err=%v", trace.Verdict, trace.NATApplied, err)
	}

	var foundSkipped, foundPolicy bool
	for _, s := range trace.Steps {
		if s.Kind == "skipped_policy" && s.RuleID == "1" {
			foundSkipped = true
		}
		if s.Kind == "policy" && s.RuleID == "10" && s.Action == "permit" {
			foundPolicy = true
		}
	}
	if !foundSkipped || !foundPolicy {
		t.Fatalf("Expected skipped_policy 1 and policy 10 permit, steps=%v", trace.Steps)
	}

	// Verify policy 30 is marked opaque due to undefined address
	var p30 *Rule
	for i := range env.Policies {
		if env.Policies[i].ID == "30" {
			p30 = &env.Policies[i]
			break
		}
	}
	if p30 == nil || p30.Action != "unknown" || !p30.Fields.Opaque {
		t.Fatalf("Policy 30 should be marked unknown and opaque, got: %v", p30)
	}
}
