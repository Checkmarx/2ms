package ruledefine

var LinkedinClientIDRegex = generateSemiGenericRegex([]string{"linked[_-]?in"}, AlphaNumeric("14"), true)

func LinkedinClientID() *Rule {
	return &Rule{
		BaseRuleID:  "3c7dba47-155c-4a27-a7a8-46cc64b61ff2",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		RuleID:      "linkedin-client-id",
		Regex:       LinkedinClientIDRegex,
		Entropy:     2,
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Severity:        "High",
		Tags:            []string{TagClientId},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 1},
	}
}
