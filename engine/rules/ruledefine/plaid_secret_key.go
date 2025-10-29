package ruledefine

var plaidSecretKeyRegex = generateSemiGenericRegex([]string{"plaid"}, AlphaNumeric("30"), true).String()

func PlaidSecretKey() *Rule {
	return &Rule{
		RuleID:      "8016c551-324e-4728-97e8-72a4fd138f01",
		Description: "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.",
		RuleName:    "Plaid-Secret-Key",
		Regex:       plaidSecretKeyRegex,
		Entropy:     3.5,
		Keywords: []string{
			"plaid",
		},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
