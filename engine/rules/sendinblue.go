package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var SendInBlueAPITokenRegex = utils.GenerateUniqueTokenRegex(`xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16}`, false)

func SendInBlueAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "8d403365-7f0f-45be-a198-2ce7c8a1becb",
		Description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
		RuleID:      "sendinblue-api-token",
		Regex:       SendInBlueAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"xkeysib-",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
