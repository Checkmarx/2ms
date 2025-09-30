package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var BittrexAccessKeyRegex = utils.GenerateSemiGenericRegex([]string{"bittrex"}, utils.AlphaNumeric("32"), true)

func BittrexAccessKey() *NewRule {
	return &NewRule{
		Description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
		RuleID:      "bittrex-access-key",
		Regex:       BittrexAccessKeyRegex,
		Keywords:    []string{"bittrex"},
	}
}
