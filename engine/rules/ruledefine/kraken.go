package ruledefine

var krakenAccessTokenRegex = generateSemiGenericRegex([]string{"kraken"},
	AlphaNumericExtendedLong("80,90"), true).String()

func KrakenAccessToken() *Rule {
	return &Rule{
		RuleID:      "50472a28-1957-4e00-8e6f-ea0d987cf3ef",
		Description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
		RuleName:    "Kraken-Access-Token",
		Regex:       krakenAccessTokenRegex,
		Keywords: []string{
			"kraken",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryCryptocurrencyExchange,
		ScoreRuleType: 4,
	}
}
