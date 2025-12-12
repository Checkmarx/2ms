package ruledefine

var finicityClientSecretRegex = generateSemiGenericRegex(
	[]string{"finicity"}, AlphaNumeric("20"), true).String()

func FinicityClientSecret() *Rule {
	return &Rule{
		RuleID:        "bc48d7fc-9dca-42f9-aefe-6d38b13f28c1",
		Description:   "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
		RuleName:      "Finicity-Client-Secret",
		Regex:         finicityClientSecretRegex,
		Keywords:      []string{"finicity"},
		Severity:      "High",
		Tags:          []string{TagClientSecret},
		Category:      CategoryFinancialServices,
		ScoreRuleType: 4,
	}
}
