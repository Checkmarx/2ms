package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ConfluentAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("16"), true)

func ConfluentAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "0f1e7b5c-5411-4bc7-98b2-743ef790186a",
		Description: "Identified a Confluent Access Token, which could compromise access to streaming data platforms and sensitive data flow.",
		RuleID:      "confluent-access-token",
		Regex:       ConfluentAccessTokenRegex,

		Keywords: []string{
			"confluent",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
