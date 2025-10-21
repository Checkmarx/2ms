package ruledefine

var linearClientSecretRegex = generateSemiGenericRegex([]string{"linear"}, Hex("32"), true).String()

func LinearClientSecret() *Rule {
	return &Rule{
		BaseRuleID:      "c628a6eb-bc3a-4bfe-8ef0-8123496bd6bd",
		Description:     "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
		RuleID:          "linear-client-secret",
		Regex:           linearClientSecretRegex,
		Entropy:         2,
		Keywords:        []string{"linear"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
