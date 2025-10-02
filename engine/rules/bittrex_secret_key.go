package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BittrexSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"bittrex"}, utils.AlphaNumeric("32"), true)

func BittrexSecretKey() *NewRule {
	return &NewRule{
		BaseRuleID:      "c2329ef8-b8ac-4758-a808-c4d2058acc57",
		Description:     "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
		RuleID:          "bittrex-secret-key",
		Regex:           BittrexSecretKeyRegex,
		Keywords:        []string{"bittrex"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
	}
}
