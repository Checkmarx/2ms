package ruledefine

var linkedinClientIDRegex = generateSemiGenericRegex(
	[]string{"linked[_-]?in"}, AlphaNumeric("14"), true).String()

func LinkedinClientID() *Rule {
	return &Rule{
		RuleID:      "3c7dba47-155c-4a27-a7a8-46cc64b61ff2",
		Description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
		RuleName:    "Linkedin-Client-Id",
		Regex:       linkedinClientIDRegex,
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
