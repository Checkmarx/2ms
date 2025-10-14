package ruledefine

var DatabricksApiTokenRegex = generateUniqueTokenRegex(`dapi[a-f0-9]{32}(?:-\d)?`, false)

func Databricks() *Rule {
	return &Rule{
		BaseRuleID:      "0d6c06db-760d-4414-920e-4f1670c23169",
		Description:     "Uncovered a Databricks API token, which may compromise big data analytics platforms and sensitive data processing.",
		RuleID:          "databricks-api-token",
		Regex:           DatabricksApiTokenRegex,
		Entropy:         3,
		Keywords:        []string{"dapi"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryDataAnalytics, RuleType: 4},
	}
}
