package ruledefine

var sendGridAPITokenRegex = generateUniqueTokenRegex(`SG\.(?i)[a-z0-9=_\-\.]{66}`, false).String()

func SendGridAPIToken() *Rule {
	return &Rule{
		RuleID:      "f117161b-1d02-423a-afb1-47a8f2c9e3ed",
		Description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
		RuleName:    "sendgrid-api-token",
		Regex:       sendGridAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"SG.",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryEmailDeliveryService, RuleType: 4},
	}
}
