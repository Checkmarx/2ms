package ruledefine

var mailgunPrivateAPITokenRegex = generateSemiGenericRegex(
	[]string{"mailgun"}, `key-[a-f0-9]{32}`, true).String()

func MailGunPrivateAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "edb6d469-f6ab-427f-9d91-93ed56c17784",
		Description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
		RuleID:      "mailgun-private-api-token",
		Regex:       mailgunPrivateAPITokenRegex,
		Keywords: []string{
			"mailgun",
		},
		Severity:        "High",
		Tags:            []string{TagPrivateKey},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
