package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var KucoinSecretKeyRegex = utils.GenerateSemiGenericRegex([]string{"kucoin"}, utils.Hex8_4_4_4_12(), true)

func KucoinSecretKey() *Rule {
	return &Rule{
		BaseRuleID:  "9c810a46-3a16-435d-b0f9-cd1b6eb30b33",
		Description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
		RuleID:      "kucoin-secret-key",
		Regex:       KucoinSecretKeyRegex,
		Keywords: []string{
			"kucoin",
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryCryptocurrencyExchange, RuleType: 4},
	}
}
