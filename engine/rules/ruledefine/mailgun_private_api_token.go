package ruledefine

var MailgunPrivateAPITokenRegex = generateSemiGenericRegex([]string{"mailgun"}, `key-[a-f0-9]{32}`, true)

func MailGunPrivateAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "edb6d469-f6ab-427f-9d91-93ed56c17784",
		Description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
		RuleID:      "mailgun-private-api-token",
		Regex:       MailgunPrivateAPITokenRegex,
		Keywords: []string{
			"mailgun",
		},
		Severity:        "High",
		Tags:            []string{TagPrivateKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
