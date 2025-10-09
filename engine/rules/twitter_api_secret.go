package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var TwitterAPISecretRegex = utils.GenerateSemiGenericRegex([]string{"twitter"}, utils.AlphaNumeric("50"), true)

func TwitterAPISecret() *Rule {
	return &Rule{
		BaseRuleID:      "d1d00b76-8fa2-4276-8f1f-43440a2d2777",
		Description:     "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
		RuleID:          "twitter-api-secret",
		Regex:           TwitterAPISecretRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
