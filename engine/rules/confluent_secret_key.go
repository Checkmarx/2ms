package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var ConfluentSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"confluent"}, utils.AlphaNumeric("64"), true)

func ConfluentSecretKey() *NewRule {
	return &NewRule{
		BaseRuleID:  "0f1e7b5c-5411-4bc7-98b2-743ef790186a",
		Description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
		RuleID:      "confluent-secret-key",
		Regex:       ConfluentSecretKeyRegex,

		Keywords: []string{
			"confluent",
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
