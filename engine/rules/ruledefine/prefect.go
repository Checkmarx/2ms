package ruledefine

var prefectRegex = generateUniqueTokenRegex(`pnu_[a-zA-Z0-9]{36}`, false).String()

func Prefect() *Rule {
	return &Rule{
		BaseRuleID:  "8c26d49d-e93b-4cd9-a564-1662f9a4be44",
		Description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
		RuleID:      "prefect-api-token",
		Regex:       prefectRegex,
		Entropy:     2,
		Keywords: []string{
			"pnu_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
