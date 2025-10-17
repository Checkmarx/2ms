package ruledefine

var squareAccessTokenRegex = generateUniqueTokenRegex(`(?:EAAA|sq0atp-)[\w-]{22,60}`, false).String()

func SquareAccessToken() *Rule {
	return &Rule{
		BaseRuleID:      "736ab85d-4250-4162-b3ff-7375fdf697a4",
		Description:     "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
		RuleID:          "square-access-token",
		Regex:           squareAccessTokenRegex,
		Entropy:         2,
		Keywords:        []string{"sq0atp-", "EAAA"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryPaymentProcessing, RuleType: 4},
	}
}
