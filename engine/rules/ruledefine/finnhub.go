package ruledefine

var finnhubAccessTokenRegex = generateSemiGenericRegex(
	[]string{"finnhub"}, AlphaNumeric("20"), true).String()

func FinnhubAccessToken() *Rule {
	return &Rule{
		RuleID:      "c91b2611-9756-4f63-b820-a236ece07b6b",
		Description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
		RuleName:    "finnhub-access-token",
		Regex:       finnhubAccessTokenRegex,
		Keywords: []string{
			"finnhub",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
