package ruledefine

var jwtRegex = generateUniqueTokenRegex(
	`ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?`, false).String()

func JWT() *Rule {
	return &Rule{
		RuleID:        "37dfe666-1961-48f8-b618-fa6321c216d1",
		Description:   "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
		RuleName:      "Jwt",
		Regex:         jwtRegex,
		Entropy:       3,
		Keywords:      []string{"ey"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryGeneralOrUnknown,
		ScoreRuleType: 4,
	}
}
