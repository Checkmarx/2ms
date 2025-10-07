package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AdobeClientSecretRegex = utils.GenerateUniqueTokenRegex(`p8e-(?i)[a-z0-9]{32}`, false)

func AdobeClientSecret() *NewRule {
	// define rule
	return &NewRule{
		BaseRuleID: "4d0dc375-5c50-4c2d-9bb7-c57677c085c1",
		RuleID:     "adobe-client-secret",
		Description: "Discovered a potential Adobe Client Secret, which," +
			" if exposed, could allow unauthorized Adobe service access and data manipulation.",
		Regex:           AdobeClientSecretRegex,
		Entropy:         2,
		Keywords:        []string{"p8e-"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
