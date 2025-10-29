package ruledefine

var kucoinAccessTokenRegex = generateSemiGenericRegex([]string{"kucoin"}, Hex("24"), true).String()

func KucoinAccessToken() *Rule {
	return &Rule{
		RuleID:      "64f3a17f-4d12-4527-b176-9b01fdffb496",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		RuleName:    "Kucoin-Access-Token",
		Regex:       kucoinAccessTokenRegex,
		Keywords: []string{
			"kucoin",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
	}
}
