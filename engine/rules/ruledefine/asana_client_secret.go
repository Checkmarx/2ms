package ruledefine

var asanaClientSecretRegex = generateSemiGenericRegex([]string{"asana"}, AlphaNumeric("32"), true)

func AsanaClientSecret() *Rule {
	return &Rule{
		BaseRuleID: "9cdadce5-a506-4a7a-b178-4970d0aadd6d",
		Description: "Identified an Asana Client Secret," +
			" which could lead to compromised project management integrity and unauthorized access.",
		RuleID:          "asana-client-secret",
		Regex:           asanaClientSecretRegex,
		Keywords:        []string{"asana"},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategoryProjectManagement, RuleType: 4},
	}
}
