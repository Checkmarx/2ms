package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CoinbaseAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"coinbase"},
	utils.AlphaNumericExtendedShort("64"), true)

func CoinbaseAccessToken() *NewRule {
	return &NewRule{
		Description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
		RuleID:      "coinbase-access-token",
		Regex:       CoinbaseAccessTokenRegex,
		Keywords: []string{
			"coinbase",
		},
	}
}
