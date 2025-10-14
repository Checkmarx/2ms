package ruledefine

var MessagebirdAPITokenRegex = generateSemiGenericRegex([]string{"message[_-]?bird"}, AlphaNumeric("25"), true)

func MessageBirdAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "9eda5e69-4034-4cc3-b4ab-966ff7ac67bd",
		Description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
		RuleID:      "messagebird-api-token",
		Regex:       MessagebirdAPITokenRegex,
		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
