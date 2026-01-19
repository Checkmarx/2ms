package ruledefine

var flyIOAccessTokenRegex = generateUniqueTokenRegex(
	`(?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3})`,
	false).String()

func FlyIOAccessToken() *Rule {
	return &Rule{
		RuleID:        "d2410346-1a57-45a0-94a3-67e185a7ac3a",
		RuleName:      "Flyio-Access-Token",
		Description:   "Uncovered a Fly.io API key",
		Regex:         flyIOAccessTokenRegex,
		Entropy:       4,
		Keywords:      []string{"fo1_", "fm1", "fm2_"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryWebHostingAndDeployment,
		ScoreRuleType: 4,
	}
}
