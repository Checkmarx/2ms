package rules

var TravisCIAccessTokenRegex = generateSemiGenericRegex([]string{"travis"}, AlphaNumeric("22"), true)

func TravisCIAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "d36da935-cc3f-41f6-8407-585c71b140d9",
		Description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
		RuleID:      "travisci-access-token",
		Regex:       TravisCIAccessTokenRegex,
		Keywords: []string{
			"travis",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
