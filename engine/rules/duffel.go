package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var DuffelAPITokenRegex = regexp.MustCompile(`duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`)

func Duffel() *NewRule {
	return &NewRule{
		BaseRuleID:      "4ae9586d-956a-43ef-807f-ae1c420ba2a8",
		Description:     "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
		RuleID:          "duffel-api-token",
		Regex:           DuffelAPITokenRegex,
		Entropy:         2,
		Keywords:        []string{"duffel_"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
