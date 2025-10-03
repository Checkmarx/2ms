package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

func OldPlaidAccessID() *config.Rule {
	return &config.Rule{
		RuleID:      "plaid-client-id",
		Description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
		Regex:       generateSemiGenericRegex([]string{"plaid"}, alphaNumeric("24"), true),

		Entropy: 3.0,
		Keywords: []string{
			"plaid",
		},
	}
}
