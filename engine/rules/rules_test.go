package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/config"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func TestLoadAllRules(t *testing.T) {
	rules := GetDefaultRules(false)

	if len(rules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestLoadAllRulesCheckFields(t *testing.T) {
	ruleIDMap := make(map[string]bool)
	baseRuleIDMap := make(map[string]bool)
	allRules := GetDefaultRules(false)
	allRules = append(allRules, getSpecialRules()...)

	for i, rule := range allRules {
		// Verify existence of all required fields
		assert.NotEqual(t, "", rule.RuleName, "rule %d: RuleName is not defined for rule %s", i, rule.RuleID)
		assert.NotEqual(t, "", rule.RuleID, "rule %d: RuleID is not defined for rule %s", i, rule.RuleName)
		assert.Nil(t, uuid.Validate(rule.RuleID), "rule %d: RuleID is not a valid uuid %s", i, rule.RuleName)
		assert.NotEqual(t, "", rule.Description, "rule %d: Description is not defined for rule %s", i, rule.RuleName)
		assert.NotEqual(t, "", rule.Severity, "rule %d: Severity is not defined for rule %s", i, rule.RuleName)
		assert.Contains(t, ruledefine.SeverityOrder, rule.Severity, "rule %d: Severity %s is not an acceptable severity (%s), in rule %s", i,
			rule.Severity, ruledefine.SeverityOrder, rule.RuleName)
		assert.NotEqual(t, "", rule.Regex, "rule %d: Regex is not defined for rule %s", i, rule.RuleName)
		// Check for ScoreParameters
		assert.NotEqual(t, ruledefine.RuleCategory(""), rule.ScoreParameters.Category, "rule %d: ScoreParameters.Category is not defined for rule %s", i, rule.RuleName)
		assert.NotEqual(t, uint8(0), rule.ScoreParameters.RuleType, "rule %d: ScoreParameters.RuleType is not defined for rule %s", i, rule.RuleName)

		// Verify duplicate rule names
		if _, ok := ruleIDMap[rule.RuleName]; ok {
			t.Errorf("duplicate rule name found: %s", rule.RuleName)
		}

		// Verify duplicate rule ids
		if _, ok := baseRuleIDMap[rule.RuleID]; ok {
			t.Errorf("duplicate rule base id found: %s", rule.RuleID)
		}

		ruleIDMap[rule.RuleName] = true
		baseRuleIDMap[rule.RuleID] = true
	}
}

func Test_FilterRules_SelectRules(t *testing.T) {
	specialRule := ruledefine.HardcodedPassword()
	allRules := GetDefaultRules(false)
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
			selectedList: []string{allRules[0].RuleName},
			ignoreList:   []string{},
			expectedLen:  1,
		},
		{
			name:         "selected flag used for multiple rules",
			selectedList: []string{allRules[0].RuleName, allRules[1].RuleName},
			ignoreList:   []string{},
			expectedLen:  2,
		},
		{
			name:         "ignore flag used for one rule",
			selectedList: []string{},
			ignoreList:   []string{allRules[0].RuleName},
			expectedLen:  rulesCount - 1,
		},
		{
			name:         "ignore flag used for multiple rules",
			selectedList: []string{},
			ignoreList:   []string{allRules[0].RuleName, allRules[1].RuleName},
			expectedLen:  rulesCount - 2,
		},
		{
			name:         "selected and ignore flags used together for different rules",
			selectedList: []string{allRules[0].RuleName},
			ignoreList:   []string{allRules[1].RuleName},
			expectedLen:  1,
		},
		{
			name:         "selected and ignore flags used together for the same rule",
			selectedList: []string{allRules[0].RuleName},
			ignoreList:   []string{allRules[0].RuleName},
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
			specialList:  []string{specialRule.RuleName},
			expectedLen:  rulesCount + 1,
		},
		{
			name:         "select regular rule and special rule",
			selectedList: []string{allRules[0].RuleName},
			ignoreList:   []string{},
			specialList:  []string{specialRule.RuleName},
			expectedLen:  2,
		},
		{
			name:         "select regular rule and ignore it- should keep it",
			selectedList: []string{"non-existent-tag-name"},
			ignoreList:   []string{specialRule.RuleName},
			specialList:  []string{specialRule.RuleName},
			expectedLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := FilterRules(tt.selectedList, tt.ignoreList, tt.specialList, []*ruledefine.Rule{}, false)

			if len(secrets) != tt.expectedLen {
				t.Errorf("expected %d rules, but got %d", tt.expectedLen, len(secrets))
			}
		})
	}
}

func TestSelectRules(t *testing.T) {
	testCases := []struct {
		name           string
		allRules       []*ruledefine.Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "No matching tags",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag5", "tag6"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Matching rule ID",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag and rule ID",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1", "tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching multiple tags",
			allRules: []*ruledefine.Rule{
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
					if result[ruleID].RuleName != expectedRule.RuleID {
						t.Errorf("Expected rule %s to have RuleName %s, but it had RuleName %s", ruleID, expectedRule.RuleID, result[ruleID].RuleName)
					}
				}
			}
		})
	}
}

func createRule(ruleID string, tags ...string) *ruledefine.Rule {
	return &ruledefine.Rule{
		RuleName: ruleID,
		Tags:     tags,
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

func rulesToMap(rules []*ruledefine.Rule) map[string]ruledefine.Rule {
	rulesMap := make(map[string]ruledefine.Rule)
	for _, rule := range rules {
		rulesMap[rule.RuleName] = *rule
	}
	return rulesMap
}

func TestIgnoreRules(t *testing.T) {
	tests := []struct {
		name           string
		allRules       []*ruledefine.Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "Empty list",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore non-existing tag",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"non-existing-tag"},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore one rule ID",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule2"),
		},
		{
			name: "Ignore one tag",
			allRules: []*ruledefine.Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag2"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Ignore all tags",
			allRules: []*ruledefine.Rule{
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

			for _, rule := range tt.allRules {
				if _, ok := tt.expectedResult[rule.RuleName]; ok {
					if _, ok := gotResult[rule.RuleName]; !ok {
						t.Errorf("expected rule %s to be present, but it was not", rule.RuleName)
					}
				} else {
					if _, ok := gotResult[rule.RuleName]; ok {
						t.Errorf("expected rule %s to be ignored, but it was not", rule.RuleName)
					}
				}
			}
		})
	}
}

func TestConvertRuleNames(t *testing.T) {
	defaultRules := GetDefaultRules(false)
	for _, rule := range defaultRules {
		ruleName := rule.RuleName
		caser := cases.Title(language.English)
		if strings.Contains(ruleName, "-") {
			ruleName = caser.String(ruleName)
		}
		fmt.Println(ruleName)
	}
}
