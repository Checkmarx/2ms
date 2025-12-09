package ruledefine

var adobeClientIDRegex = generateSemiGenericRegex([]string{"adobe"}, Hex("32"), true).String()

func AdobeClientID() *Rule {
	// define rule
	return &Rule{
		RuleID:   "59599f26-ea9c-495c-b47f-c69433002c45",
		RuleName: "Adobe-Client-Id",
		Description: "Detected a pattern that resembles an Adobe OAuth Web Client ID," +
			" posing a risk of compromised Adobe integrations and data breaches.",
		Regex:         adobeClientIDRegex,
		Entropy:       2,
		Keywords:      []string{"adobe"},
		Severity:      "High",
		Tags:          []string{TagClientId},
		Category:      CategorySaaS,
		ScoreRuleType: 1,
	}
}
