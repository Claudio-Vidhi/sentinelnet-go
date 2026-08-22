package policytest

func witnessFor(rule Rule, boundIngress string) map[string]any {
	if rule.Fields.Opaque || len(rule.Fields.NarrowingQuals) > 0 {
		return nil
	}
	example := GenerateRuleExample(rule, nil)
	if example.MatchingFlow == nil {
		return nil
	}
	flow := example.MatchingFlow.ToMap()
	if boundIngress != "" {
		if _, ok := flow["ingress_intf"]; !ok || flow["ingress_intf"] == "" {
			flow["ingress_intf"] = boundIngress
		}
	}
	return flow
}

// FindRulesetDefects analyzes a single RuleSet for shadowed, unreachable, any_any, and unresolved rules.
func FindRulesetDefects(ruleset *RuleSet) []Finding {
	var findings []Finding
	var activeRules []Rule
	for _, r := range ruleset.Rules {
		if !r.Disabled {
			activeRules = append(activeRules, r)
		}
	}

	var coveringAnyAny *Rule

	for idx, rule := range activeRules {
		// 1. Unresolved objects
		if len(rule.Unresolved) > 0 {
			findings = append(findings, Finding{
				Key:        "unresolved_object",
				Severity:   "medium",
				RuleID:     rule.ID,
				ACLName:    ruleset.Name,
				Params:     map[string]any{"rule_id": rule.ID, "objects": rule.Unresolved, "acl": ruleset.Name},
				MessageKey: "finding.unresolved_object",
			})
		}

		// 2. Unreachable check
		if coveringAnyAny != nil {
			severity := "medium"
			if rule.Action == "permit" {
				severity = "high"
			}
			findings = append(findings, Finding{
				Key:            "unreachable",
				Severity:       severity,
				RuleID:         rule.ID,
				ACLName:        ruleset.Name,
				Params:         map[string]any{"rule_id": rule.ID, "blocked_by": coveringAnyAny.ID, "acl": ruleset.Name},
				MessageKey:     "finding.unreachable",
				Witness:        witnessFor(rule, ""),
				ExpectedRuleID: coveringAnyAny.ID,
			})
			continue
		}

		// 3. Any-any permit check
		if rule.Action == "permit" && rule.Fields.IsAnyAny() {
			findings = append(findings, Finding{
				Key:        "any_any",
				Severity:   "high",
				RuleID:     rule.ID,
				ACLName:    ruleset.Name,
				Params:     map[string]any{"rule_id": rule.ID, "acl": ruleset.Name},
				MessageKey: "finding.any_any",
			})
		}

		// 4. Shadow check
		if !rule.Fields.Opaque {
			for _, prev := range activeRules[:idx] {
				if !prev.Fields.Opaque && prev.Fields.Contains(rule.Fields) {
					severity := "low"
					if prev.Action != rule.Action {
						severity = "high"
					}
					findings = append(findings, Finding{
						Key:      "shadowed",
						Severity: severity,
						RuleID:   rule.ID,
						ACLName:  ruleset.Name,
						Params: map[string]any{
							"rule_id":     rule.ID,
							"shadowed_by": prev.ID,
							"acl":         ruleset.Name,
							"prev_action": prev.Action,
							"curr_action": rule.Action,
						},
						MessageKey:     "finding.shadowed",
						Witness:        witnessFor(rule, ""),
						ExpectedRuleID: prev.ID,
					})
					break
				}
			}
		}

		// Update covering any-any tracker
		if !rule.Fields.Opaque && rule.Fields.IsAnyAny() {
			ruleCopy := rule
			coveringAnyAny = &ruleCopy
		}
	}

	return findings
}

// FindRoutingDefects checks for static routes to nowhere (next hop not in any connected subnet).
func FindRoutingDefects(routeTable RouteTable) []Finding {
	var findings []Finding
	connected := routeTable.ConnectedSubnets()

	for _, r := range routeTable.Routes {
		if r.Source == "static" && r.NextHop != "" && r.Interface == "" {
			nhInt, err := IPToInt(r.NextHop)
			if err != nil {
				findings = append(findings, Finding{
					Key:        "route_to_nowhere",
					Severity:   "high",
					Params:     map[string]any{"prefix": r.Prefix, "next_hop": r.NextHop},
					MessageKey: "finding.route_to_nowhere",
				})
				continue
			}
			hasConnected := false
			for _, c := range connected {
				if c.PrefixCube.ContainsIP(nhInt) {
					hasConnected = true
					break
				}
			}
			if !hasConnected {
				findings = append(findings, Finding{
					Key:        "route_to_nowhere",
					Severity:   "high",
					Params:     map[string]any{"prefix": r.Prefix, "next_hop": r.NextHop},
					MessageKey: "finding.route_to_nowhere",
				})
			}
		}
	}

	return findings
}

// AnalyzePolicyFindings collects all static findings from an IOS or FortiOS environment.
func AnalyzePolicyFindings(env any) []Finding {
	var findings []Finding

	switch e := env.(type) {
	case *IOSPolicyEnvironment:
		for _, acl := range e.ACLs {
			findings = append(findings, FindRulesetDefects(acl)...)
		}
		findings = append(findings, FindRoutingDefects(e.RouteTable)...)
	case *FortiOSPolicyEnvironment:
		rs := &RuleSet{
			Name:  "firewall policy",
			Kind:  "firewall_policy",
			Rules: e.Policies,
		}
		findings = append(findings, FindRulesetDefects(rs)...)
		findings = append(findings, FindRoutingDefects(e.RouteTable)...)
	}

	return findings
}
