package ruledefine

var kucoinAccessTokenRegex = generateSemiGenericRegex([]string{"kucoin"}, Hex("24"), true)

func KucoinAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "64f3a17f-4d12-4527-b176-9b01fdffb496",
		Description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
		RuleID:      "kucoin-access-token",
		Regex:       kucoinAccessTokenRegex,
		Keywords: []string{
			"kucoin",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
	}
}
