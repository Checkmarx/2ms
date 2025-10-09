package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var SendGridAPITokenRegex = utils.GenerateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false)

func SendGridAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "f117161b-1d02-423a-afb1-47a8f2c9e3ed",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		RuleID:      "sendgrid-api-token",
		Regex:       SendGridAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"SG.",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
