package ruledefine

var typeformRegex = generateSemiGenericRegex([]string{"typeform"},
	`tfp_[a-z0-9\-_\.=]{59}`, true).String()

func Typeform() *Rule {
	return &Rule{
		BaseRuleID:  "fa7376dc-2332-4ac7-9b12-762db17de2c5",
		Description: "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.",
		RuleID:      "typeform-api-token",
		Regex:       typeformRegex,
		Keywords: []string{
			"tfp_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryOnlineSurveyPlatform, RuleType: 4},
	}
}
