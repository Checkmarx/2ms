package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var StripeAccessTokenRegex = utils.GenerateUniqueTokenRegex(`(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}`, false)

func StripeAccessToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "b44c7f22-1458-482c-8e1a-e8b3a854d7d6",
		Description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.",
		RuleID:      "stripe-access-token",
		Regex:       StripeAccessTokenRegex,
		Entropy:     2,
		Keywords: []string{
			"sk_test",
			"sk_live",
			"sk_prod",
			"rk_test",
			"rk_live",
			"rk_prod",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
