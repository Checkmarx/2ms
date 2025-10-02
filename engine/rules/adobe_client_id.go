package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

func AdobeClientID() *NewRule {
	// define rule
	return &NewRule{
		BaseRuleID:      "59599f26-ea9c-495c-b47f-c69433002c45",
		RuleID:          "adobe-client-id",
		Description:     "Detected a pattern that resembles an Adobe OAuth Web Client ID, posing a risk of compromised Adobe integrations and data breaches.",
		Regex:           utils.GenerateSemiGenericRegex([]string{"adobe"}, utils.Hex("32"), true),
		Entropy:         2,
		Keywords:        []string{"adobe"},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 1},
	}
}
