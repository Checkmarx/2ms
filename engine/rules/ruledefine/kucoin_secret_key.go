package ruledefine

var kucoinSecretKeyRegex = generateSemiGenericRegex([]string{"kucoin"}, Hex8_4_4_4_12(), true).String()

func KucoinSecretKey() *Rule {
	return &Rule{
		RuleID:      "9c810a46-3a16-435d-b0f9-cd1b6eb30b33",
		Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
		RuleName:    "Kucoin-Secret-Key",
		Regex:       kucoinSecretKeyRegex,
		Keywords: []string{
			"kucoin",
		},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategoryCryptocurrencyExchange,
		ScoreRuleType: 4,
	}
}
