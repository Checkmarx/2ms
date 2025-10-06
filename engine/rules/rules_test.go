package rules

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestLoadAllRules(t *testing.T) {
	rules := GetDefaultRules()

	if len(rules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestLoadAllRules_DuplicateRuleID(t *testing.T) {
	ruleIDMap := make(map[string]bool)
	allRules := GetDefaultRules()

	for _, rule := range allRules {
		if _, ok := ruleIDMap[rule.Rule.RuleID]; ok {
			t.Errorf("duplicate rule id found: %s", rule.Rule.RuleID)
		}

		ruleIDMap[rule.Rule.RuleID] = true
	}
}

func Test_FilterRules_SelectRules(t *testing.T) {
	specialRule := HardcodedPassword()
	allRules := GetDefaultRules()
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
			secrets := FilterRules(tt.selectedList, tt.ignoreList, tt.specialList)

			if len(secrets) != tt.expectedLen {
				t.Errorf("expected %d rules, but got %d", tt.expectedLen, len(secrets))
			}
		})
	}
}

func TestSelectRules(t *testing.T) {
	testCases := []struct {
		name           string
		allRules       []*Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "No matching tags",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag5", "tag6"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Matching rule ID",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching tag and rule ID",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag3", "tag4"),
			},
			tags:           []string{"rule1", "tag2"},
			expectedResult: createRules("rule1"),
		},
		{
			name: "Matching multiple tags",
			allRules: []*Rule{
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

func createRule(ruleID string, tags ...string) *Rule {
	return &Rule{
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

func rulesToMap(rules []*Rule) map[string]config.Rule {
	rulesMap := make(map[string]config.Rule)
	for _, rule := range rules {
		rulesMap[rule.Rule.RuleID] = rule.Rule
	}
	return rulesMap
}

func TestIgnoreRules(t *testing.T) {
	tests := []struct {
		name           string
		allRules       []*Rule
		tags           []string
		expectedResult map[string]config.Rule
	}{
		{
			name: "Empty list",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore non-existing tag",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"non-existing-tag"},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore one rule ID",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule2"),
		},
		{
			name: "Ignore one tag",
			allRules: []*Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag2"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Ignore all tags",
			allRules: []*Rule{
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

func TestOldVsNewRulesEqual(t *testing.T) {
	// These should be defined in your package
	allRules := GetDefaultRules()
	allRules2 := GetDefaultRulesV2()

	compareRules(t, allRules, allRules2)
}

func compareRules(t *testing.T, allRules []*Rule, allRules2 []*NewRule) {
	if len(allRules) != len(allRules2) {
		t.Errorf("rule count mismatch: got %d, want %d", len(allRules), len(allRules2))
	}
	var rulesWithAllowList []string
	baseRuleIDsMap := make(map[string]bool)
	for i := range allRules {
		r1 := allRules[i]
		r2 := allRules2[i]

		// Severity
		assert.Equal(t, "High", r2.Severity, "[%d] Wrong Severity on rule %s", i, r2.RuleID)

		// Check for unique baseRuleIDs
		assert.NotEqual(t, "", r2.BaseRuleID, "[%d] No BaseRuleId found on rule %s", i, r2.RuleID)
		assert.Nil(t, uuid.Validate(r2.BaseRuleID), "[%d] BaseRuleID %s is not a valid UUID", i, r2.BaseRuleID)
		_, ok := baseRuleIDsMap[r2.BaseRuleID]
		assert.False(t, ok, "[%d] BaseRuleID %s already found in another rule", i, r2.BaseRuleID)
		baseRuleIDsMap[r2.BaseRuleID] = true

		//TODO: Create test for severity
		//TODO: check what's happening with keywords
		//TODO: Create a test for allowList
		//TODO: check presence of baseRuleID, as well as uniqueness of uuids

		if r1.Rule.RuleID != r2.RuleID {
			t.Fatalf("[%d] RuleID mismatch: got %s, want %s", i, r2.RuleID, r1.Rule.RuleID)
		}

		// Tags
		assert.Equal(t, r1.Rule.Description, r2.Description, "[%d] Description mismatch on rule %s", i, r1.Rule.RuleID)

		// Entropy exclusions
		entropyExclusions := map[string]bool{
			"github-app-token":    true,
			"plaid-client-id":     true,
			"vault-service-token": true,
		}

		// Entropy
		if !entropyExclusions[r1.Rule.RuleID] {
			assert.Equal(t, r1.Rule.Entropy, r2.Entropy, "[%d] Entropy mismatch on rule %s: got %v, want %v", i, r1.Rule.RuleID, r2.Entropy, r1.Rule.Entropy)
		}

		if r1.Rule.SecretGroup != r2.SecretGroup {
			t.Errorf("[%d] SecretGroup mismatch: got %v, want %v", i, r2.SecretGroup, r1.Rule.SecretGroup)
		}

		// Regex string comparison
		if r1.Rule.RuleID != "plaid-client-id" {
			if !compareRegex(r1.Rule.Regex, r2.Regex) {
				t.Errorf("[%d] Regex mismatch on rule %s: got %v, want %v", i, r1.Rule.RuleID, r2.Regex, r1.Rule.Regex)
			}
		}

		// Path regex
		if !compareRegex(r1.Rule.Path, r2.Path) {
			t.Errorf("[%d] Path mismatch: got %v, want %v", i, r2.Path, r1.Rule.Path)
		}

		// Tags
		assert.Equal(t, r1.Tags, r2.Tags, "[%d] Tags mismatch on rule %s", i, r1.Rule.RuleID)

		// Keywords
		// Normalize keywords to lowercase for comparison because validate on gitleaks side performs strings.ToLower(keyword)
		for j := range r2.Keywords {
			r2.Keywords[j] = strings.ToLower(r2.Keywords[j])
		}
		for k := range r1.Rule.Keywords {
			r1.Rule.Keywords[k] = strings.ToLower(r1.Rule.Keywords[k])
		}

		if r1.Rule.RuleID != "vault-service-token" { // for these rules keywords were updated with latest version of gitleaks
			assert.Equal(t, r1.Rule.Keywords, r2.Keywords, "[%d] Keywords mismatch on rule %s", i, r1.Rule.RuleID)
		}
		// Score Parameters
		if r1.ScoreParameters != r2.ScoreParameters {
			t.Errorf("[%d] ScoreParameters mismatch on rule %s: got %+v, want %+v", i, r1.Rule.RuleID, r2.ScoreParameters, r1.ScoreParameters)
		}

		if r1.Rule.Allowlists != nil {
			rulesWithAllowList = append(rulesWithAllowList, r1.Rule.RuleID)
			// AllowList
			for i2 := range r1.Rule.Allowlists {
				al1 := r1.Rule.Allowlists[i2]
				al2 := r2.AllowLists[i2]

				assert.Equal(t, al1.Description, al2.Description, "[%d][%d] Allowlist description mismatch on rule %s", i, i2, r1.Rule.RuleID)
				assert.Equal(t, al1.MatchCondition, toGitleaksMatchCondition(al2.MatchCondition), "[%d][%d] Allowlist MatchCondition mismatch on rule %s", i, i2, r1.Rule.RuleID)
				assert.Equal(t, al1.RegexTarget, al2.RegexTarget, "[%d][%d] Allowlist RegexTarget mismatch on rule %s", i, i2, r1.Rule.RuleID)
				assert.Equal(t, al1.StopWords, al2.StopWords, "[%d][%d] Allowlist StopWords mismatch on rule %s", i, i2, r1.Rule.RuleID)

				// Paths
				for j := range al1.Paths {
					if !compareRegex(al1.Paths[j], al2.Paths[j]) {
						t.Errorf("[%d][%d][%d] Allowlist Paths regex mismatch on rule %s: got %v, want %v", i, i2, j, r1.Rule.RuleID, al2.Paths[j], al1.Paths[j])
					}
				}

				// Regexes
				for j := range al1.Regexes {
					if !compareRegex(al1.Regexes[j], al2.Regexes[j]) {
						t.Errorf("[%d][%d][%d] Allowlist Regexes regex mismatch on rule %s: got %v, want %v", i, i2, j, r1.Rule.RuleID, al2.Regexes[j], al1.Regexes[j])
					}
				}
			}
		}

	}
	// Log all rules with allowList
	fmt.Printf("Rules with allowList: %v\n", rulesWithAllowList)
}

func compareRegex(r1, r2 *regexp.Regexp) bool {
	if r1 == nil && r2 == nil {
		return true
	}
	if r1 == nil || r2 == nil {
		return false
	}
	return r1.String() == r2.String()
}
