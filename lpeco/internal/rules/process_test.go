package rules

import (
	"context"
	"testing"
)

func TestProcessRuleFixtures(t *testing.T) {
	fixture := loadRuleFixture(t, "../../testdata/rules/process/scenarios.json")
	rules := rulesByID(PrimaryRules())
	for _, scenario := range fixture.Cases {
		t.Run(scenario.Name, func(t *testing.T) {
			rule, ok := rules[scenario.RuleID]
			if !ok {
				t.Fatalf("rule %q not registered", scenario.RuleID)
			}
			candidates := EvaluateAll(context.Background(), graphFromFixture(t, scenario), []Rule{rule})
			assertScenario(t, scenario, candidates)
		})
	}
}
