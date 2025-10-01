package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var KrakenAccessTokenRegex = utils.GenerateSemiGenericRegex([]string{"kraken"},
	utils.AlphaNumericExtendedLong("80,90"), true)

func KrakenAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "50472a28-1957-4e00-8e6f-ea0d987cf3ef",
		Description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
		RuleID:      "kraken-access-token",
		Regex:       KrakenAccessTokenRegex,
		Keywords: []string{
			"kraken",
		},
		Severity: "High",
	}
}
