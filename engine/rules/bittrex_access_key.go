package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BittrexAccessKeyRegex = utils.GenerateSemiGenericRegex([]string{"bittrex"}, utils.AlphaNumeric("32"), true)

func BittrexAccessKey() *NewRule {
	return &NewRule{
		BaseRuleID: "aa773e5a-097f-4bc5-8de1-916651d4a046",
		Description: "Identified a Bittrex Access Key," +
			" which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
		RuleID:          "bittrex-access-key",
		Regex:           BittrexAccessKeyRegex,
		Keywords:        []string{"bittrex"},
		Severity:        "High",
		Tags:            []string{TagAccessKey},
		ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
	}
}
