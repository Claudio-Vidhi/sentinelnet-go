package policytest

import (
	"fmt"
	"strings"
)

func ruleStopsWalk(rule Rule, flow Flow) bool {
	if rule.Fields.Opaque || len(rule.Unresolved) > 0 {
		return rule.Fields.MayMatch(flow)
	}
	return rule.Fields.Matches(flow)
}

func firstMatch(rules []Rule, flow Flow) *Rule {
	for i := range rules {
		if ruleStopsWalk(rules[i], flow) {
			return &rules[i]
		}
	}
	return nil
}

func findInterface(interfaces map[string]map[string]any, name string) map[string]any {
	if name == "" {
		return nil
	}
	if entry, ok := interfaces[name]; ok {
		return entry
	}
	low := strings.ToLower(name)
	for ifaceName, info := range interfaces {
		if strings.ToLower(ifaceName) == low {
			return info
		}
	}
	return nil
}

func deriveIngressIntf(srcIP string, routeTable RouteTable) string {
	ipVal, err := IPToInt(srcIP)
	if err != nil {
		return ""
	}
	for _, r := range routeTable.ConnectedSubnets() {
		if r.PrefixCube.ContainsIP(ipVal) {
			return r.Interface
		}
	}
	return ""
}

// EvaluateIOS evaluates a Flow through a Cisco IOS policy and routing environment.
func EvaluateIOS(env *IOSPolicyEnvironment, flow Flow) Trace {
	var steps []Step
	unresolved := append([]string{}, env.Unresolved...)
	dynamicPresent := env.RouteTable.DynamicRoutingPresent

	// 1. Determine Ingress Interface
	ingress := flow.IngressIntf
	if ingress == "" {
		ingress = deriveIngressIntf(flow.SrcIP, env.RouteTable)
	}

	evaluatedFlow := Flow{
		SrcIP:       flow.SrcIP,
		DstIP:       flow.DstIP,
		Proto:       flow.Proto,
		SPort:       flow.SPort,
		DPort:       flow.DPort,
		IngressIntf: ingress,
		EgressIntf:  flow.EgressIntf,
		TCPFlags:    flow.TCPFlags,
		Established: flow.Established,
		ICMPType:    flow.ICMPType,
	}

	// 2. Ingress ACL evaluation
	ifaceInfo := findInterface(env.Interfaces, ingress)
	if ifaceInfo != nil {
		aclInName, _ := ifaceInfo["acl_in"].(string)
		if aclInName != "" && env.ACLs[aclInName] != nil {
			acl := env.ACLs[aclInName]
			matchedRule := firstMatch(acl.Rules, evaluatedFlow)

			if matchedRule != nil {
				matchedDesc := "rule"
				if matchedRule.ID != "" {
					matchedDesc = fmt.Sprintf("seq %s", matchedRule.ID)
				}
				if len(matchedRule.Unresolved) > 0 || matchedRule.Fields.Opaque {
					steps = append(steps, Step{
						Kind:     "acl_in",
						ACL:      aclInName,
						Matched:  matchedDesc,
						Action:   "unknown",
						RuleID:   matchedRule.ID,
						RawText:  matchedRule.RawText,
						Note:     "unresolved or opaque ACE",
					})
					return Trace{
						Verdict:               "UNKNOWN",
						Steps:                 steps,
						ImplicitDeny:          false,
						DynamicRoutingPresent: dynamicPresent,
						Unresolved:            append(unresolved, matchedRule.Unresolved...),
						Flow:                  evaluatedFlow.ToMap(),
					}
				} else if matchedRule.Action == "deny" {
					steps = append(steps, Step{
						Kind:    "acl_in",
						ACL:     aclInName,
						Matched: matchedDesc,
						Action:  "deny",
						RuleID:  matchedRule.ID,
						RawText: matchedRule.RawText,
					})
					return Trace{
						Verdict:               "DENY",
						Steps:                 steps,
						ImplicitDeny:          false,
						DynamicRoutingPresent: dynamicPresent,
						Unresolved:            unresolved,
						Flow:                  evaluatedFlow.ToMap(),
					}
				} else {
					steps = append(steps, Step{
						Kind:    "acl_in",
						ACL:     aclInName,
						Matched: matchedDesc,
						Action:  "permit",
						RuleID:  matchedRule.ID,
						RawText: matchedRule.RawText,
					})
				}
			} else {
				// Implicit deny
				steps = append(steps, Step{
					Kind:    "acl_in",
					ACL:     aclInName,
					Matched: "implicit deny",
					Action:  "deny",
					Note:    "implicit deny at end of ACL",
				})
				return Trace{
					Verdict:               "DENY",
					Steps:                 steps,
					ImplicitDeny:          true,
					DynamicRoutingPresent: dynamicPresent,
					Unresolved:            unresolved,
					Flow:                  evaluatedFlow.ToMap(),
				}
			}
		} else {
			steps = append(steps, Step{
				Kind:   "acl_in",
				Action: "permit",
				Note:   fmt.Sprintf("no inbound ACL bound on %s", ingress),
			})
		}
	} else if ingress != "" {
		steps = append(steps, Step{
			Kind:   "acl_in",
			Action: "unknown",
			Note:   fmt.Sprintf("interface %s does not exist on this device", ingress),
		})
		return Trace{
			Verdict:               "UNKNOWN",
			Steps:                 steps,
			ImplicitDeny:          false,
			DynamicRoutingPresent: dynamicPresent,
			Unresolved:            append(unresolved, fmt.Sprintf("ingress interface '%s' is not configured on this device", ingress)),
			Flow:                  evaluatedFlow.ToMap(),
		}
	} else {
		steps = append(steps, Step{
			Kind:   "acl_in",
			Action: "permit",
			Note:   "ingress interface unknown; inbound ACL skipped",
		})
	}

	// 3. Route Lookup
	route := env.RouteTable.Lookup(flow.DstIP)
	if route == nil {
		steps = append(steps, Step{
			Kind:    "route",
			Matched: "no_static_route",
			Action:  "unknown",
			Note:    "no connected or static route found for destination",
		})
		return Trace{
			Verdict:               "UNKNOWN",
			Steps:                 steps,
			ImplicitDeny:          false,
			DynamicRoutingPresent: dynamicPresent,
			Unresolved:            unresolved,
			Flow:                  evaluatedFlow.ToMap(),
		}
	}

	egress := route.Interface
	evaluatedFlow.EgressIntf = egress
	steps = append(steps, Step{
		Kind:    "route",
		Prefix:  route.Prefix,
		NextHop: route.NextHop,
		Egress:  egress,
		Source:  route.Source,
		Action:  "permit",
	})

	// 4. Egress ACL evaluation
	outIfaceInfo := findInterface(env.Interfaces, egress)
	if outIfaceInfo != nil {
		aclOutName, _ := outIfaceInfo["acl_out"].(string)
		if aclOutName != "" && env.ACLs[aclOutName] != nil {
			acl := env.ACLs[aclOutName]
			matchedRule := firstMatch(acl.Rules, evaluatedFlow)

			if matchedRule != nil {
				matchedDesc := "rule"
				if matchedRule.ID != "" {
					matchedDesc = fmt.Sprintf("seq %s", matchedRule.ID)
				}
				if len(matchedRule.Unresolved) > 0 || matchedRule.Fields.Opaque {
					steps = append(steps, Step{
						Kind:     "acl_out",
						ACL:      aclOutName,
						Matched:  matchedDesc,
						Action:   "unknown",
						RuleID:   matchedRule.ID,
						RawText:  matchedRule.RawText,
						Note:     "unresolved or opaque ACE",
					})
					return Trace{
						Verdict:               "UNKNOWN",
						Steps:                 steps,
						ImplicitDeny:          false,
						DynamicRoutingPresent: dynamicPresent,
						Unresolved:            append(unresolved, matchedRule.Unresolved...),
						Flow:                  evaluatedFlow.ToMap(),
					}
				} else if matchedRule.Action == "deny" {
					steps = append(steps, Step{
						Kind:    "acl_out",
						ACL:     aclOutName,
						Matched: matchedDesc,
						Action:  "deny",
						RuleID:  matchedRule.ID,
						RawText: matchedRule.RawText,
					})
					return Trace{
						Verdict:               "DENY",
						Steps:                 steps,
						ImplicitDeny:          false,
						DynamicRoutingPresent: dynamicPresent,
						Unresolved:            unresolved,
						Flow:                  evaluatedFlow.ToMap(),
					}
				} else {
					steps = append(steps, Step{
						Kind:    "acl_out",
						ACL:     aclOutName,
						Matched: matchedDesc,
						Action:  "permit",
						RuleID:  matchedRule.ID,
						RawText: matchedRule.RawText,
					})
				}
			} else {
				// Implicit deny
				steps = append(steps, Step{
					Kind:    "acl_out",
					ACL:     aclOutName,
					Matched: "implicit deny",
					Action:  "deny",
					Note:    "implicit deny at end of ACL",
				})
				return Trace{
					Verdict:               "DENY",
					Steps:                 steps,
					ImplicitDeny:          true,
					DynamicRoutingPresent: dynamicPresent,
					Unresolved:            unresolved,
					Flow:                  evaluatedFlow.ToMap(),
				}
			}
		} else {
			steps = append(steps, Step{
				Kind:   "acl_out",
				Action: "permit",
				Note:   "no ACL bound outbound",
			})
		}
	} else {
		steps = append(steps, Step{
			Kind:   "acl_out",
			Action: "permit",
			Note:   "no ACL bound outbound",
		})
	}

	return Trace{
		Verdict:               "PERMIT",
		Steps:                 steps,
		ImplicitDeny:          false,
		DynamicRoutingPresent: dynamicPresent,
		Unresolved:            unresolved,
		Flow:                  evaluatedFlow.ToMap(),
	}
}

// EvaluateFortiOSChain evaluates a Flow through FortiOS routing and security policies.
func EvaluateFortiOSChain(
	policies []Rule,
	routeTable RouteTable,
	flow Flow,
	unresolvedObjects []string,
) Trace {
	var steps []Step
	unresolved := append([]string{}, unresolvedObjects...)
	dynamicPresent := routeTable.DynamicRoutingPresent
	natApplied := false

	// 1. Route Lookup
	route := routeTable.Lookup(flow.DstIP)
	if route == nil {
		steps = append(steps, Step{
			Kind:    "route",
			Matched: "no_static_route",
			Action:  "unknown",
			Note:    "no connected or static route found for destination",
		})
		return Trace{
			Verdict:               "UNKNOWN",
			Steps:                 steps,
			ImplicitDeny:          false,
			DynamicRoutingPresent: dynamicPresent,
			Unresolved:            unresolved,
			Flow:                  flow.ToMap(),
		}
	}

	egress := route.Interface
	ingress := flow.IngressIntf
	if ingress == "" {
		ingress = deriveIngressIntf(flow.SrcIP, routeTable)
	}

	evaluatedFlow := Flow{
		SrcIP:       flow.SrcIP,
		DstIP:       flow.DstIP,
		Proto:       flow.Proto,
		SPort:       flow.SPort,
		DPort:       flow.DPort,
		IngressIntf: ingress,
		EgressIntf:  egress,
		TCPFlags:    flow.TCPFlags,
		Established: flow.Established,
		ICMPType:    flow.ICMPType,
	}

	steps = append(steps, Step{
		Kind:    "route",
		Prefix:  route.Prefix,
		NextHop: route.NextHop,
		Egress:  egress,
		Source:  route.Source,
		Action:  "permit",
	})

	// 2. Sequential policy evaluation
	var matchedPolicy *Rule

	for i := range policies {
		pol := &policies[i]
		if pol.Disabled {
			aclDesc := pol.Name
			if aclDesc == "" {
				aclDesc = fmt.Sprintf("policy %s", pol.ID)
			}
			steps = append(steps, Step{
				Kind:    "skipped_policy",
				ACL:     aclDesc,
				Matched: fmt.Sprintf("policy %s", pol.ID),
				Action:  "skip",
				RuleID:  pol.ID,
				Note:    "status disable",
			})
			continue
		}

		if ruleStopsWalk(*pol, evaluatedFlow) {
			matchedPolicy = pol
			break
		}
	}

	if matchedPolicy != nil {
		if matchedPolicy.NATEnabled {
			natApplied = true
		}
		aclDesc := matchedPolicy.Name
		if aclDesc == "" {
			aclDesc = fmt.Sprintf("policy %s", matchedPolicy.ID)
		}

		if len(matchedPolicy.Unresolved) > 0 || matchedPolicy.Fields.Opaque {
			note := "unresolved object"
			if len(matchedPolicy.Unresolved) > 0 {
				note = strings.Join(matchedPolicy.Unresolved, ", ")
			}
			steps = append(steps, Step{
				Kind:     "policy",
				ACL:      aclDesc,
				Matched:  fmt.Sprintf("policy %s", matchedPolicy.ID),
				Action:   "unknown",
				RuleID:   matchedPolicy.ID,
				RawText:  matchedPolicy.RawText,
				Note:     note,
			})
			return Trace{
				Verdict:               "UNKNOWN",
				Steps:                 steps,
				ImplicitDeny:          false,
				DynamicRoutingPresent: dynamicPresent,
				Unresolved:            append(unresolved, matchedPolicy.Unresolved...),
				NATApplied:            natApplied,
				Flow:                  evaluatedFlow.ToMap(),
			}
		} else if matchedPolicy.Action == "deny" || matchedPolicy.Action == "drop" {
			steps = append(steps, Step{
				Kind:    "policy",
				ACL:     aclDesc,
				Matched: fmt.Sprintf("policy %s", matchedPolicy.ID),
				Action:  "deny",
				RuleID:  matchedPolicy.ID,
				RawText: matchedPolicy.RawText,
			})
			return Trace{
				Verdict:               "DENY",
				Steps:                 steps,
				ImplicitDeny:          false,
				DynamicRoutingPresent: dynamicPresent,
				Unresolved:            unresolved,
				NATApplied:            natApplied,
				Flow:                  evaluatedFlow.ToMap(),
			}
		} else {
			steps = append(steps, Step{
				Kind:    "policy",
				ACL:     aclDesc,
				Matched: fmt.Sprintf("policy %s", matchedPolicy.ID),
				Action:  "permit",
				RuleID:  matchedPolicy.ID,
				RawText: matchedPolicy.RawText,
			})
			return Trace{
				Verdict:               "PERMIT",
				Steps:                 steps,
				ImplicitDeny:          false,
				DynamicRoutingPresent: dynamicPresent,
				Unresolved:            unresolved,
				NATApplied:            natApplied,
				Flow:                  evaluatedFlow.ToMap(),
			}
		}
	}

	// 3. Implicit deny (policy 0)
	steps = append(steps, Step{
		Kind:    "policy",
		ACL:     "default",
		Matched: "implicit deny",
		Action:  "deny",
		Note:    "implicit deny (policy 0)",
	})
	return Trace{
		Verdict:               "DENY",
		Steps:                 steps,
		ImplicitDeny:          true,
		DynamicRoutingPresent: dynamicPresent,
		Unresolved:            unresolved,
		NATApplied:            false,
		Flow:                  evaluatedFlow.ToMap(),
	}
}

// Evaluate is the generic entry point dispatching based on environment type.
func Evaluate(env any, flow Flow) (Trace, error) {
	switch e := env.(type) {
	case *IOSPolicyEnvironment:
		return EvaluateIOS(e, flow), nil
	case *FortiOSPolicyEnvironment:
		return EvaluateFortiOSChain(e.Policies, e.RouteTable, flow, e.Unresolved), nil
	default:
		return Trace{}, fmt.Errorf("unknown policy environment type: %T", env)
	}
}
