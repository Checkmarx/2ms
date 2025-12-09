package ruledefine

// regex for rule
var adafruitAPIKeyRegex = generateSemiGenericRegex(
	[]string{"adafruit"}, AlphaNumericExtendedShort("32"), true).String()

func AdafruitAPIKey() *Rule {
	// define rule
	return &Rule{
		RuleID: "c29ea920-52c4-4366-9e75-1574e286d1d7",
		Description: "Identified a potential Adafruit API Key," +
			" which could lead to unauthorized access to Adafruit services and sensitive data exposure.",
		RuleName:      "Adafruit-Api-Key",
		Regex:         adafruitAPIKeyRegex,
		Keywords:      []string{"adafruit"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryIoTPlatform,
		ScoreRuleType: 4,
	}
}
