package ruledefine

var databricksApiTokenRegex = generateUniqueTokenRegex(`dapi[a-f0-9]{32}(?:-\d)?`, false).String()

func Databricks() *Rule {
	return &Rule{
		RuleID:        "0d6c06db-760d-4414-920e-4f1670c23169",
		Description:   "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
		RuleName:      "Databricks-Api-Token",
		Regex:         databricksApiTokenRegex,
		Entropy:       3,
		Keywords:      []string{"dapi"},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryDataAnalytics,
		ScoreRuleType: 4,
	}
}
