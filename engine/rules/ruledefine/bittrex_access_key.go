package ruledefine

var bittrexAccessKeyRegex = generateSemiGenericRegex([]string{"bittrex"}, AlphaNumeric("32"), true)

func BittrexAccessKey() *Rule {
	return &Rule{
		RuleID: "aa773e5a-097f-4bc5-8de1-916651d4a046",
		Description: "Identified a Bittrex Access Key," +
			" which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
		RuleName:      "Bittrex-Access-Key",
		Regex:         bittrexAccessKeyRegex.String(),
		Keywords:      []string{"bittrex"},
		Severity:      "High",
		Tags:          []string{TagAccessKey},
		Category:      CategoryCryptocurrencyExchange,
		ScoreRuleType: 4,
	}
}
