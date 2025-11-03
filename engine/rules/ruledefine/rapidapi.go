package ruledefine

var rapidAPIAccessTokenRegex = generateSemiGenericRegex([]string{"rapidapi"},
	AlphaNumericExtendedShort("50"), true).String()

func RapidAPIAccessToken() *Rule {
	return &Rule{
		RuleID:      "f4f4feea-e8d0-4c8d-ab8f-833e673a9ff8",
		Description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
		RuleName:    "Rapidapi-Access-Token",
		Regex:       rapidAPIAccessTokenRegex,
		Keywords: []string{
			"rapidapi",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
