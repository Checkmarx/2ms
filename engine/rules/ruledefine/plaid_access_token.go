package ruledefine

var plaidAccessTokenRegex = generateSemiGenericRegex([]string{"plaid"},
	"access-(?:sandbox|development|production)-"+Hex8_4_4_4_12(), true).String()

func PlaidAccessToken() *Rule {
	return &Rule{
		RuleID:      "64838a2c-8f91-4677-8b08-a43a513b9df6",
		Description: "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.",
		RuleName:    "Plaid-Api-Token",
		Regex:       plaidAccessTokenRegex,
		Keywords: []string{
			"plaid",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
