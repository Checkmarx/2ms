package rules

import (
	"testing"

	"github.com/zricethezav/gitleaks/v8/config"
)

func TestLoadAllRules(t *testing.T) {
	rules := getDefaultRules()

	if len(*rules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestLoadAllRules_DuplicateRuleID(t *testing.T) {
	ruleIDMap := make(map[string]bool)
	allRules := getDefaultRules()

	for _, rule := range *allRules {
		if _, ok := ruleIDMap[rule.Rule.RuleID]; ok {
			t.Errorf("duplicate rule id found: %s", rule.Rule.RuleID)
		}

		ruleIDMap[rule.Rule.RuleID] = true
	}
}

func Test_FilterRules_SelectRules(t *testing.T) {
	specialRule := HardcodedPassword()
	allRules := *getDefaultRules()
	rulesCount := len(allRules)

	tests := []struct {
		name         string
		selectedList []string
		ignoreList   []string
		specialList  []string
		expectedLen  int
	}{
		{
			name:         "selected flag used for one rule",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{},
			expectedLen:  1,
		},
		{
			name:         "selected flag used for multiple rules",
			selectedList: []string{allRules[0].Rule.RuleID, allRules[1].Rule.RuleID},
			ignoreList:   []string{},
			expectedLen:  2,
		},
		{
			name:         "ignore flag used for one rule",
			selectedList: []string{},
			ignoreList:   []string{allRules[0].Rule.RuleID},
			expectedLen:  rulesCount - 1,
		},
		{
			name:         "ignore flag used for multiple rules",
			selectedList: []string{},
			ignoreList:   []string{allRules[0].Rule.RuleID, allRules[1].Rule.RuleID},
			expectedLen:  rulesCount - 2,
		},
		{
			name:         "selected and ignore flags used together for different rules",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{allRules[1].Rule.RuleID},
			expectedLen:  1,
		},
		{
			name:         "selected and ignore flags used together for the same rule",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{allRules[0].Rule.RuleID},
			expectedLen:  0,
		},
		{
			name:         "non existent select flag",
			selectedList: []string{"non-existent-tag-name"},
			ignoreList:   []string{},
			expectedLen:  0,
		},
		{
			name:         "non existent ignore flag",
			selectedList: []string{},
			ignoreList:   []string{"non-existent-tag-name"},
			expectedLen:  rulesCount,
		},
		{
			name:         "no flags",
			selectedList: []string{},
			ignoreList:   []string{},
			expectedLen:  rulesCount,
		},
		{
			name:         "add special rule",
			selectedList: []string{},
			ignoreList:   []string{},
			specialList:  []string{specialRule.RuleID},
			expectedLen:  rulesCount + 1,
		},
		{
			name:         "select regular rule and special rule",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{},
			specialList:  []string{specialRule.RuleID},
			expectedLen:  2,
		},
		{
			name:         "select regular rule and ignore it- should keep it",
			selectedList: []string{"non-existent-tag-name"},
			ignoreList:   []string{specialRule.RuleID},
			specialList:  []string{specialRule.RuleID},
			expectedLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := *FilterRules(tt.selectedList, tt.ignoreList, tt.specialList)

			if len(secrets) != tt.expectedLen {
				t.Errorf("expected %d rules, but got %d", tt.expectedLen, len(secrets))
			}
		})
	}
}

func TestSelectRules(t *testing.T) {
	testCases := []struct {
		name           string
		allRules       *[]Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "No matching tags",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag5", "tag6"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Matching rule ID",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag and rule ID",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1", "tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching multiple tags",
			allRules: &[]Rule{
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
			result := rulesToMap(selectRules(tc.allRules, tc.tags))

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

func rulesToMap(rules *[]Rule) map[string]config.Rule {
	rulesMap := make(map[string]config.Rule)
	for _, rule := range *rules {
		rulesMap[rule.Rule.RuleID] = rule.Rule
	}
	return rulesMap
}

func TestIgnoreRules(t *testing.T) {
	tests := []struct {
		name           string
		allRules       *[]Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "Empty list",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore non-existing tag",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"non-existing-tag"},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore one rule ID",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule2"),
		},
		{
			name: "Ignore one tag",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag2"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Ignore all tags",
			allRules: &[]Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag1", "tag2", "tag3"},
			expectedResult: map[string]config.Rule{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotResult := rulesToMap(ignoreRules(tt.allRules, tt.tags))

			if len(gotResult) != len(tt.expectedResult) {
				t.Errorf("expected %d rules, but got %d", len(tt.expectedResult), len(gotResult))
			}

			for _, rule := range *tt.allRules {
				if _, ok := tt.expectedResult[rule.Rule.RuleID]; ok {
					if _, ok := gotResult[rule.Rule.RuleID]; !ok {
						t.Errorf("expected rule %s to be present, but it was not", rule.Rule.RuleID)
					}
				} else {
					if _, ok := gotResult[rule.Rule.RuleID]; ok {
						t.Errorf("expected rule %s to be ignored, but it was not", rule.Rule.RuleID)
					}
				}
			}
		})
	}
}
