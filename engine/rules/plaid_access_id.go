package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var PlaidAccessIDRegex = utils.GenerateSemiGenericRegex([]string{"plaid"}, utils.AlphaNumeric("24"), true)

func PlaidAccessID() *NewRule {
	return &NewRule{
		BaseRuleID:  "9f80861a-c2b5-423a-9f8f-81203da136dc",
		RuleID:      "plaid-client-id",
		Description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
		Regex:       PlaidAccessIDRegex,
		Entropy:     3.5,
		Keywords: []string{
			"plaid",
		},
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 1},
	}
}
