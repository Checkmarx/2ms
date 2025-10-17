package ruledefine

var infracostAPITokenRegex = generateUniqueTokenRegex(`ico-[a-zA-Z0-9]{32}`, false).String()

func InfracostAPIToken() *Rule {
	return &Rule{
		BaseRuleID:      "0774bdec-232f-4c68-8ba0-458f5e1e40c8",
		Description:     "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",
		RuleID:          "infracost-api-token",
		Regex:           infracostAPITokenRegex,
		Entropy:         3,
		Keywords:        []string{"ico-"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryFinancialServices, RuleType: 4},
	}
}
