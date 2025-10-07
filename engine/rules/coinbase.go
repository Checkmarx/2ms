package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CoinbaseAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"coinbase"},
	utils.AlphaNumericExtendedShort("64"), true)

func CoinbaseAccessToken() *NewRule {
	return &NewRule{
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
