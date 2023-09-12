package secrets

import (
	"fmt"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TestLoadAllRules(t *testing.T) {
	rules := loadDefaultRules()

	if len(rules) <= 1 {
		t.Error("no rules were loaded")
	}
}

func TestLoadAllRules_DuplicateRuleID(t *testing.T) {
	ruleIDMap := make(map[string]bool)
	allRules := loadDefaultRules()

	for _, rule := range allRules {
		if _, ok := ruleIDMap[rule.Rule.RuleID]; ok {
			t.Errorf("duplicate rule id found: %s", rule.Rule.RuleID)
		}

		ruleIDMap[rule.Rule.RuleID] = true
	}
}

func Test_Init_SelectRules(t *testing.T) {
	allRules := loadDefaultRules()
	rulesCount := len(allRules)

	tests := []struct {
		name         string
		selectedList []string
		ignoreList   []string
		expectedErr  error
		expectedLen  int
	}{
		{
			name:         "selected flag used for one rule",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{},
			expectedErr:  nil,
			expectedLen:  1,
		},
		{
			name:         "selected flag used for multiple rules",
			selectedList: []string{allRules[0].Rule.RuleID, allRules[1].Rule.RuleID},
			ignoreList:   []string{},
			expectedErr:  nil,
			expectedLen:  2,
		},
		{
			name:         "ignore flag used for one rule",
			selectedList: []string{},
			ignoreList:   []string{allRules[0].Rule.RuleID},
			expectedErr:  nil,
			expectedLen:  rulesCount - 1,
		},
		{
			name:         "ignore flag used for multiple rules",
			selectedList: []string{},
			ignoreList:   []string{allRules[0].Rule.RuleID, allRules[1].Rule.RuleID},
			expectedErr:  nil,
			expectedLen:  rulesCount - 2,
		},
		{
			name:         "selected and ignore flags used together for different rules",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{allRules[1].Rule.RuleID},
			expectedErr:  nil,
			expectedLen:  1,
		},
		{
			name:         "selected and ignore flags used together for the same rule",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{allRules[0].Rule.RuleID},
			expectedErr:  fmt.Errorf("no rules were selected"),
			expectedLen:  0,
		},
		{
			name:         "non existent select flag",
			selectedList: []string{"non-existent-tag-name"},
			ignoreList:   []string{},
			expectedErr:  fmt.Errorf("no rules were selected"),
			expectedLen:  0,
		},
		{
			name:         "non existent ignore flag",
			selectedList: []string{},
			ignoreList:   []string{"non-existent-tag-name"},
			expectedErr:  nil,
			expectedLen:  rulesCount,
		},
		{
			name:         "no flags",
			selectedList: []string{},
			ignoreList:   []string{},
			expectedErr:  nil,
			expectedLen:  rulesCount,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := Init(tt.selectedList, tt.ignoreList)

			if err != nil {
				if tt.expectedErr == nil {
					t.Errorf("expected no error, but got %s", err)
				} else if err.Error() == tt.expectedErr.Error() {
					return
				} else {
					t.Errorf("expected error '%s', but got '%s'", tt.expectedErr, err)
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

func rulesToMap(rules []Rule) map[string]config.Rule {
	rulesMap := make(map[string]config.Rule)
	for _, rule := range rules {
		rulesMap[rule.Rule.RuleID] = rule.Rule
	}
	return rulesMap
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

func TestIgnoreRules(t *testing.T) {
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
			name: "Ignore non-existing tag",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"non-existing-tag"},
			expectedResult: createRules("rule1", "rule2"),
		},
		{
			name: "Ignore one rule ID",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"rule1"},
			expectedResult: createRules("rule2"),
		},
		{
			name: "Ignore one tag",
			allRules: []Rule{
				createRule("rule1", "tag1", "tag2"),
				createRule("rule2", "tag2", "tag3"),
			},
			tags:           []string{"tag2"},
			expectedResult: map[string]config.Rule{},
		},
		{
			name: "Ignore all tags",
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

func TestSecrets(t *testing.T) {
	secrets := []struct {
		Content    string
		Name       string
		ShouldFind bool
	}{
		{
			Content:    "",
			Name:       "empty",
			ShouldFind: false,
		},
		{
			Content:    "mongodb+srv://radar:mytoken@io.dbb.mongodb.net/?retryWrites=true&w=majority",
			Name:       "Authenticated URL",
			ShouldFind: true,
		},
		{
			Content:    "--output=https://elastic:bF21iC0bfTVXo3qhpJqTGs78@c22f5bc9787c4c268d3b069ad866bdc2.eu-central-1.aws.cloud.es.io:9243/tfs",
			Name:       "Authenticated URL",
			ShouldFind: true,
		},
		{
			Content:    "https://abc:123@google.com",
			Name:       "Basic Authenticated URL",
			ShouldFind: true,
		},
		{
			Content:    "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",
			Name:       "GitHub Personal Access Token",
			ShouldFind: true,
		},
		{
			Content: "AKCp8jRRiQSAbghbuZmHKZcaKGEqbAASGH2SAb3rxXJQsSq9dGga8gFXe6aHpcRmzuHxN6oaT",
			Name:    "JFROG Secret without keyword",
			// gitleaks is using "keywords" to identify the next literal after the keyword is a secret,
			// that is why we are not expecting to find this secret
			ShouldFind: false,
		},
		{
			Content:    "--set imagePullSecretJfrog.password=AKCp8kqqfQbYifrbyvqusjyk6N3QKprXTv9B8HTitLbJzXT1kW7dDticXTsJpCrbqtizAwK4D \\",
			Name:       "JFROG Secret with keyword (real example)",
			ShouldFind: true,
		},
		{
			Content:    "--docker-password=AKCp8kqX8yeKBTqgm2XExHsp8yVdJn6SAgQmS1nJMfMDmzxEqX74rUGhedaWu7Eovid3VsMwb",
			Name:       "JFROG Secret as kubectl argument",
			ShouldFind: true,
		},
	}

	detector, err := Init([]string{}, []string{})
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range secrets {
		name := secret.Name
		if name == "" {
			name = secret.Content
		}
		t.Run(name, func(t *testing.T) {
			fmt.Printf("Start test %s", name)
			secretsChan := make(chan reporting.Secret, 1)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			detector.Detect(plugins.Item{Content: secret.Content}, secretsChan, wg, nil)
			close(secretsChan)

			s := <-secretsChan
			if s.Value == "" && secret.ShouldFind {
				t.Errorf("secret \"%s\" not found", secret.Name)
			}
			if s.Value != "" && !secret.ShouldFind {
				t.Errorf("should not find")
			}
		})
	}

}
