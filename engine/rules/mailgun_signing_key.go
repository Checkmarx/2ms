package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var MailgunSigningKeyRegex = utils.GenerateSemiGenericRegex([]string{"mailgun"}, `[a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8}`, true)

func MailGunSigningKey() *Rule {
	return &Rule{
		BaseRuleID:  "b06b485a-b4aa-4f18-9ff9-6a9ff59fc961",
		Description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
		RuleID:      "mailgun-signing-key",
		Regex:       MailgunSigningKeyRegex,
		Keywords: []string{
			"mailgun",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
