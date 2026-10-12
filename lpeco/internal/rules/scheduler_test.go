package rules

import (
	"context"
	"testing"
)

func TestSchedulerRuleFixtures(t *testing.T) {
	testRuleFixtureFile(t, "../../testdata/rules/scheduler/scenarios.json")
}

func testRuleFixtureFile(t *testing.T, path string) {
	t.Helper()
	fixture := loadRuleFixture(t, path)
	rules := rulesByID(AllRules())
	for _, scenario := range fixture.Cases {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			rule, ok := rules[scenario.RuleID]
			if !ok {
				t.Fatalf("rule %q not registered", scenario.RuleID)
			}
			evaluation := Evaluate(context.Background(), graphFromFixture(t, scenario), []Rule{rule})
			assertScenario(t, scenario, evaluation.Candidates)
			if scenario.WantDiagnostic != "" && !hasRuleDiagnostic(evaluation.Diagnostics, scenario.WantDiagnostic) {
				t.Fatalf("diagnostics = %#v, want %q", evaluation.Diagnostics, scenario.WantDiagnostic)
			}
		})
	}
}

func hasRuleDiagnostic(values []Diagnostic, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}
