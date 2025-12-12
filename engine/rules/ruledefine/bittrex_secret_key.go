package ruledefine

var bittrexSecretKeyRegex = generateSemiGenericRegex([]string{"bittrex"}, AlphaNumeric("32"), true)

func BittrexSecretKey() *Rule {
	return &Rule{
		RuleID:        "c2329ef8-b8ac-4758-a808-c4d2058acc57",
		Description:   "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
		RuleName:      "Bittrex-Secret-Key",
		Regex:         bittrexSecretKeyRegex.String(),
		Keywords:      []string{"bittrex"},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategoryCryptocurrencyExchange,
		ScoreRuleType: 4,
	}
}
