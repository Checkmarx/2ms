package ruledefine

var gocardlessAPITokenRegex = generateSemiGenericRegex(
	[]string{"gocardless"}, `live_(?i)[a-z0-9\-_=]{40}`, true).String()

func GoCardless() *Rule {
	return &Rule{
		BaseRuleID: "abdf0043-764e-4903-b1a8-e03b7bd59e46",
		Description: "Detected a GoCardless API token," +
			" potentially risking unauthorized direct debit payment operations and financial data exposure.",
		RuleID: "gocardless-api-token",
		Regex:  gocardlessAPITokenRegex,
		Keywords: []string{
			"live_",
			"gocardless",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
