package rules

var CoinbaseAccessTokenRegex = generateSemiGenericRegex([]string{"coinbase"},
	AlphaNumericExtendedShort("64"), true)

func CoinbaseAccessToken() *Rule {
	return &Rule{
		BaseRuleID: "8bdcb3ab-5e18-4e26-b0af-b69252618e03",
		Description: "Detected a Coinbase Access Token," +
			" posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
		RuleID: "coinbase-access-token",
		Regex:  CoinbaseAccessTokenRegex,
		Keywords: []string{
			"coinbase",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
	}
}
