package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/detect"
	"strings"
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

func Test2msRules(t *testing.T) {
	testRules := map[string]struct {
		rule           config.Rule
		truePositives  []string
		falsePositives []string
	}{
		"authenticated-url": {
			rule: *AuthenticatedURL(),
			truePositives: []string{
				"mongodb+srv://radar:mytoken@io.dbb.mongodb.net/?retryWrites=true&w=majority",
				"--output=https://elastic:bF21iC0bfTVXo3qhpJqTGs78@c22f5bc9787c4c268d3b069ad866bdc2.eu-central-1.aws.cloud.es.io:9243/tfs",
				"https://abc:123@google.com",
			},
			falsePositives: []string{
				"https://google.com",
				"https://google.com?user=abc&password=123",
				`<img src="https://img.shields.io/static/v1?label=Threads&message=Follow&color=101010&link=https://threads.net/@mathrunet" alt="Follow on Threads" />`,
				`my [Linkedin](https://www.linkedin.com/in/rodriguesjeffdev/) or email: rodriguesjeff.dev@gmail.com`,
				`[![Gmail Badge](https://img.shields.io/badge/-VaibhavHariramani-d54b3d?style=flat-circle&labelColor=d54b3d&logo=gmail&logoColor=white&link=mailto:vaibhav.hariramani01@gmail.com)](mailto:vaibhav.hariramani01@gmail.com)`,
				`https://situmops:$(github_token)@github.com/$(Build.Repository.Name).git`,
				`'$cmd "unilinks://@@malformed.invalid.url/path?"$cmdSuffix',`,
				`Uri.parse('http://login:password@192.168.0.1:8888'),`,
			},
		},
		"hardcoded-password": {
			rule: *HardcodedPassword(),
			truePositives: []string{
				`"client_id" : "0afae57f3ccfd9d7f5767067bc48b30f719e271ba470488056e37ab35d4b6506"`,
				`"client_secret" : "6da89121079f83b2eb6acccf8219ea982c3d79bccc3e9c6a85856480661f8fde",`,
				`"password: 'edf8f16608465858a6c9e3cccb97d3c2'"`,
				`<element password="edf8f16608465858a6c9e3cccb97d3c2" />`,
				`"client_id" : "edf8f16608465858a6c9e3cccb97d3c2"`,
				"https://google.com?user=abc&password=1234",
				`{ "access-key": "6da89121079f83b2eb6acccf8219ea982c3d79bccc", }`,
				`"{ \"access-key\": \"6da89121079f83b2eb6acccf8219ea982c3d79bccc\", }"`,
				"<password>edf8f16608465858a6c9e3cccb97d3c2</password>",
				"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
				`"client_secret" : "4v7b9n2k5h",`, // entropy: 3.32
				`"password: 'comp123!'"`,
				"<password>MyComp9876</password>", // entropy: 3.32
				`<element password="Comp4567@@" />`,
				"M_DB_PASSWORD= edf8f16608465858a6c9e3cccb97d3c2",
			},
			falsePositives: []string{
				`client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.client-vpn-endpoint.id`,
				`password combination.

				R5: Regulatory--21`,
				"GITHUB_TOKEN: ${GITHUB_TOKEN}",
				"password = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'", // Stop word
				"password = 'your_password_here'",               // Stop word
			},
		},
		"plaid-client-id": {
			rule: *PlaidAccessID(),
			truePositives: []string{
				generateSampleSecret("plaid", secrets.NewSecret(alphaNumeric("24"))),
			},
			falsePositives: nil,
		},
		"private-key": {
			rule: *PrivateKey(),
			truePositives: []string{`-----BEGIN PRIVATE KEY-----
		anything
		-----END PRIVATE KEY-----`,
				`-----BEGIN RSA PRIVATE KEY-----
		abcdefghijklmnopqrstuvwxyz
		-----END RSA PRIVATE KEY-----
		`,
				`-----BEGIN PRIVATE KEY BLOCK-----
		anything
		-----END PRIVATE KEY BLOCK-----`,
			},
			falsePositives: nil,
		},
		"vault-service-token": {
			rule: *VaultServiceToken(),
			truePositives: []string{
				generateSampleSecret("vault", "hvs."+secrets.NewSecret(alphaNumericExtendedShort("90"))),
			},
			falsePositives: nil,
		},
	}

	for ruleID, data := range testRules {
		t.Run(ruleID, func(t *testing.T) {
			// Copied from https://github.com/gitleaks/gitleaks/blob/463d24618fa42fc7629dc30c9744ebe36c5df1ab/cmd/generate/config/rules/rule.go
			var keywords []string
			for _, k := range data.rule.Keywords {
				keywords = append(keywords, strings.ToLower(k))
			}
			data.rule.Keywords = keywords

			rules := make(map[string]config.Rule)
			rules[data.rule.RuleID] = data.rule
			d := detect.NewDetector(config.Config{
				Rules:    rules,
				Keywords: keywords,
			})
			for _, tp := range data.truePositives {
				if len(d.DetectString(tp)) != 1 {
					t.Errorf("Failed to validate. True positive %s was not detected by regex for rule %s", tp, data.rule.RuleID)
				}
			}
			for _, fp := range data.falsePositives {
				if len(d.DetectString(fp)) != 0 {
					t.Errorf("Failed to validate. False positive %s was detected by regex for rule %s", fp, data.rule.RuleID)
				}
			}
		})
	}
}
