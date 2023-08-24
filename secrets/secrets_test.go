package secrets

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
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

func TestSecrets(t *testing.T) {
	secrets := []struct {
		Content    string
		Name       string
		ShouldFind bool
	}{
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

func TestAllGitleaksRulesAreUsed(t *testing.T) {

	// Import the rules from "gitleak"
	remoteURL := "https://raw.githubusercontent.com/gitleaks/gitleaks/master/cmd/generate/config/main.go"

	response, err := http.Get(remoteURL)
	if err != nil {
		fmt.Printf("Failed to fetch remote file: %v\n", err)
		return
	}
	defer response.Body.Close()

	content, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Failed to read remote file content: %v\n", err)
		return
	}

	re := regexp.MustCompile(`configRules\s*=\s*append\(configRules,\s*rules\.([a-zA-Z0-9_]+)\(`)

	matches := re.FindAllStringSubmatch(string(content), -1)

	var gitleaksRules []string

	for _, match := range matches {

		gitleaksRules = append(gitleaksRules, match[1])

	}

	//Import the rules from our project "2ms"
	localContent, err := os.ReadFile("secrets.go")
	if err != nil {
		t.Fatalf("Failed to read local file content: %v", err)
	}
	localRegex2 := regexp.MustCompile(`allRules\s*=\s*append\(allRules,\s*Rule{Rule:\s*\*rules\.([a-zA-Z0-9_]+)\(\),`)
	ourRules := localRegex2.FindAllStringSubmatch(string(localContent), -1)

	localRulesMap := make(map[string]bool)

	for _, match := range ourRules {
		localRulesMap[match[1]] = true
	}

	//compare the rules and check if missing ruels in our list of ruels

	missingInLocal := []string{}
	for _, rule := range gitleaksRules {
		if _, found := localRulesMap[rule]; !found {
			missingInLocal = append(missingInLocal, rule)
		}
	}

	if len(missingInLocal) > 0 {
		t.Errorf("Test failed. Differences found:\n")
		if len(missingInLocal) > 0 {
			fmt.Printf("Rules missing in local but present in gitleaks:\n")
			for _, rule := range missingInLocal {
				fmt.Printf("%s\n", rule)
			}
		}

	}
}
