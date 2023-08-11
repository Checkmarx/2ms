package secrets

import (
	"fmt"
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
)

func TestLoadAllRules(t *testing.T) {
	rules, _ := loadAllRules()

	if len(rules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestLoadAllRules_DuplicateRuleID(t *testing.T) {
	ruleIDMap := make(map[string]bool)
	allRules, err := loadAllRules()
	if err != nil {
		t.Error(err)
	}

	for _, rule := range allRules {
		if _, ok := ruleIDMap[rule.Rule.RuleID]; ok {
			t.Errorf("duplicate rule id found: %s", rule.Rule.RuleID)
		}

		ruleIDMap[rule.Rule.RuleID] = true
	}
}

func TestLoadAllRules_CustomRulesLoaded(t *testing.T) {
	allRules, err := loadAllRules()
	ruleIDMap := make(map[string]bool)
	if err != nil {
		t.Error(err)
	}

	for _, rule := range allRules {
		ruleIDMap[rule.Rule.RuleID] = true
	}
	for _, customRule := range customRules {
		_, ok := ruleIDMap[customRule.RuleID]
		if !ok {
			t.Errorf("custom rule not found: %s", customRule.RuleID)
		}
	}
}

func TestIsAllFilter_AllFilterNotPresent(t *testing.T) {
	filters := []string{"token", "key"}

	isAllFilter := isAllFilter(filters)

	if isAllFilter {
		t.Errorf("all rules were not selected")
	}
}

func TestIsAllFilter_AllFilterPresent(t *testing.T) {
	filters := []string{"token", "key", "all"}

	isAllFilter := isAllFilter(filters)

	if !isAllFilter {
		t.Errorf("all filter selected")
	}
}

func TestIsAllFilter_OnlyAll(t *testing.T) {
	filters := []string{"all"}

	isAllFilter := isAllFilter(filters)

	if !isAllFilter {
		t.Errorf("all filter selected")
	}
}

func TestGetRules_AllFilter(t *testing.T) {
	rules, _ := loadAllRules()
	tags := []string{"all"}

	filteredRules := getRules(rules, tags)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_TokenFilter(t *testing.T) {
	rules, _ := loadAllRules()
	tags := []string{"api-token"}

	filteredRules := getRules(rules, tags)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_KeyFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"api-key"}

	filteredRules := getRules(rules, filters)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_IdFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"access-token"}

	filteredRules := getRules(rules, filters)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestGetRules_IdAndKeyFilters(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"api-key", "access-token"}

	filteredRules := getRules(rules, filters)

	if len(filteredRules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestInit(t *testing.T) {
	allRules, err := loadAllRules()
	if err != nil {
		t.Error(err)
	}
	rulesCount := len(allRules)

	tests := []struct {
		name        string
		includeList []string
		excludeList []string
		expectedErr error
		expectedLen int
	}{
		{
			name:        "include and exclude flags used together",
			includeList: []string{"tag1"},
			excludeList: []string{"tag2"},
			expectedErr: fmt.Errorf("cannot use both include and exclude flags"),
			expectedLen: 0,
		},
		{
			name:        "non existent include flag",
			includeList: []string{"non-existent-tag-name"},
			excludeList: []string{},
			expectedErr: fmt.Errorf("no rules were selected"),
			expectedLen: 0,
		},
		{
			name:        "non existent exclude flag",
			includeList: []string{},
			excludeList: []string{"non-existent-tag-name"},
			expectedErr: nil,
			expectedLen: rulesCount,
		},
		{
			name:        "no flags",
			includeList: []string{},
			excludeList: []string{},
			expectedErr: nil,
			expectedLen: rulesCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := Init(tt.includeList, tt.excludeList)

			if err != nil {
				if tt.expectedErr == nil {
					t.Errorf("expected no error, but got %s", err)
				} else if err.Error() == tt.expectedErr.Error() {
					return
				} else {
					t.Errorf("expected error %s, but got %s", tt.expectedErr, err)
				}
			} else if tt.expectedErr != nil {
				t.Errorf("expected error %s, but got none", tt.expectedErr)
			}

			if len(secrets.rules) != tt.expectedLen {
				t.Errorf("expected %d rules, but got %d", tt.expectedLen, len(secrets.rules))
			}
		})
	}
}

func TestSelectRules(t *testing.T) {
	testCases := []struct {
		name           string
		allRules       []Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "No matching tags",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag5", "tag6"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Matching rule ID",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag and rule ID",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1", "tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching multiple tags",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
				createRule("rule3", "tag2", "tag4"),
			},
			tags:           []string{"tag2", "tag4"},
			expectedResult: createRules("rule1", "rule2", "rule3"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := selectRules(tc.allRules, tc.tags)

			if len(result) != len(tc.expectedResult) {
				t.Errorf("Expected %d rules to be applied, but got %d", len(tc.expectedResult), len(result))
			}

			for ruleID, expectedRule := range tc.expectedResult {
				if _, ok := result[ruleID]; !ok {
					t.Errorf("Expected rule %s to be applied, but it was not", ruleID)
				} else {
					if result[ruleID].RuleID != expectedRule.RuleID {
						t.Errorf("Expected rule %s to have RuleID %s, but it had RuleID %s", ruleID, expectedRule.RuleID, result[ruleID].RuleID)
					}
				}
			}
		})
	}
}

func TestExcludeRules(t *testing.T) {
	tests := []struct {
		name           string
		allRules       []Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "Empty list",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Exclude non-existing tag",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"non-existing-tag"},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Exclude one rule ID",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule2"),
		},
		{
			name: "Exclude one tag",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag2"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Exclude all tags",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag1", "tag2", "tag3"},
			expectedResult: map[string]config.Rule{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := excludeRules(tt.allRules, tt.tags)

			if len(gotResult) != len(tt.expectedResult) {
				t.Errorf("expected %d rules, but got %d", len(tt.expectedResult), len(gotResult))
			}

			for _, rule := range tt.allRules {
				if _, ok := tt.expectedResult[rule.Rule.RuleID]; ok {
					if _, ok := gotResult[rule.Rule.RuleID]; !ok {
						t.Errorf("expected rule %s to be present, but it was not", rule.Rule.RuleID)
					}
				} else {
					if _, ok := gotResult[rule.Rule.RuleID]; ok {
						t.Errorf("expected rule %s to be excluded, but it was not", rule.Rule.RuleID)
					}
				}
			}
		})
	}
}

func createRule(ruleID string, tags ...string) Rule {
	return Rule{
		Rule: config.Rule{
			RuleID: ruleID,
		},
		Tags: tags,
	}
}

func createRules(ruleIDs ...string) map[string]config.Rule {
	rules := make(map[string]config.Rule)
	for _, ruleID := range ruleIDs {
		rules[ruleID] = config.Rule{
			RuleID: ruleID,
		}
	}
	return rules
}
