package ruledefine

// regex for rule
var AdafruitAPIKeyRegex = generateSemiGenericRegex([]string{"adafruit"}, AlphaNumericExtendedShort("32"), true)

func AdafruitAPIKey() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "c29ea920-52c4-4366-9e75-1574e286d1d7",
		Description: "Identified a potential Adafruit API Key," +
			" which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleID:          "adafruit-api-key",
		Regex:           AdafruitAPIKeyRegex,
		Keywords:        []string{"adafruit"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryIoTPlatform, RuleType: 4},
	}
}
