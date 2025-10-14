package ruledefine

var AsanaClientIdRegex = generateSemiGenericRegex([]string{"asana"}, Numeric("16"), true)

func AsanaClientID() *Rule {
	return &Rule{
		BaseRuleID:      "f26c0989-82cb-41d1-a30e-80202e933565",
		Description:     "Discovered a potential Asana Client ID, risking unauthorized access to Asana projects and sensitive task information.",
		RuleID:          "asana-client-id",
		Regex:           AsanaClientIdRegex,
		Keywords:        []string{"asana"},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategoryProjectManagement, RuleType: 1},
	}
}
