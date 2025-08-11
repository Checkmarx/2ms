package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

// Using this local version because gitleaks has entropy as 3.5, which causes issues on this rule's validation
func PlaidAccessID() *config.Rule {
	// define rule
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
