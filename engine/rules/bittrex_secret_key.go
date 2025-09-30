package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BittrexSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"bittrex"}, utils.AlphaNumeric("32"), true)

func BittrexSecretKey() *NewRule {
	return &NewRule{
		Description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
		RuleID:      "bittrex-secret-key",
		Regex:       BittrexSecretKeyRegex,
		Keywords:    []string{"bittrex"},
	}
}
