package ruledefine

var travisCIAccessTokenRegex = generateSemiGenericRegex([]string{"travis"}, AlphaNumeric("22"), true).String()

func TravisCIAccessToken() *Rule {
	return &Rule{
		RuleID:      "d36da935-cc3f-41f6-8407-585c71b140d9",
		Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
		RuleName:    "Travisci-Access-Token",
		Regex:       travisCIAccessTokenRegex,
		Keywords: []string{
			"travis",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryCICD,
		ScoreRuleType: 4,
	}
}
