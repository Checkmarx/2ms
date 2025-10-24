package ruledefine

import (
	"regexp"
)

var duffelAPITokenRegex = regexp.MustCompile(`duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`).String()

func Duffel() *Rule {
	return &Rule{
		RuleID:          "4ae9586d-956a-43ef-807f-ae1c420ba2a8",
		Description:     "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
		RuleName:        "duffel-api-token",
		Regex:           duffelAPITokenRegex,
		Entropy:         2,
		Keywords:        []string{"duffel_"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
