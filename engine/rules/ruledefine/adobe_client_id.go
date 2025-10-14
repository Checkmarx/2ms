package ruledefine

var AdobeClientIDRegex = generateSemiGenericRegex([]string{"adobe"}, Hex("32"), true)

func AdobeClientID() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "59599f26-ea9c-495c-b47f-c69433002c45",
		RuleID:     "adobe-client-id",
		Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID," +
			" posing a risk of compromised Adobe integrations and data breaches.",
		Regex:           AdobeClientIDRegex,
		Entropy:         2,
		Keywords:        []string{"adobe"},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 1},
	}
}
