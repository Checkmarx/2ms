package ruledefine

var FinicityAPITokenRegex = generateSemiGenericRegex([]string{"finicity"}, Hex("32"), true)

func FinicityAPIToken() *Rule {
	return &Rule{
		BaseRuleID:      "e16fe1d1-5312-455f-a9c2-0cf1879c81cb",
		Description:     "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
		RuleID:          "finicity-api-token",
		Regex:           FinicityAPITokenRegex,
		Keywords:        []string{"finicity"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
