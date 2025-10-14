package ruledefine

var MessagebirdClientIDRegex = generateSemiGenericRegex([]string{"message[_-]?bird"}, Hex8_4_4_4_12(), true)

func MessageBirdClientID() *Rule {
	return &Rule{
		BaseRuleID:  "bb630684-0bfe-457e-bf74-55d655c2011a",
		Description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
		RuleID:      "messagebird-client-id",
		Regex:       MessagebirdClientIDRegex,
		Keywords: []string{
			"messagebird",
			"message-bird",
			"message_bird",
		},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
	}
}
