package ruledefine

import (
	"regexp"
)

var LinearAPIKeyRegex = regexp.MustCompile(`lin_api_(?i)[a-z0-9]{40}`)

func LinearAPIToken() *Rule {
	return &Rule{
		BaseRuleID:      "e366eacb-5244-4f4b-8a09-bb3c3da9c621",
		Description:     "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
		RuleID:          "linear-api-key",
		Regex:           LinearAPIKeyRegex,
		Entropy:         2,
		Keywords:        []string{"lin_api_"},
		Severity:        "High",
		Tags:            []string{TagApiToken, TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
