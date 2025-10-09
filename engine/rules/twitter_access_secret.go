package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var TwitterAccessSecretRegex = utils.GenerateSemiGenericRegex([]string{"twitter"}, utils.AlphaNumeric("45"), true)

func TwitterAccessSecret() *Rule {
	return &Rule{
		BaseRuleID:      "ff86e24f-7ee8-4a9e-8107-f9e26f354247",
		Description:     "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
		RuleID:          "twitter-access-secret",
		Regex:           TwitterAccessSecretRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagPublicSecret},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
