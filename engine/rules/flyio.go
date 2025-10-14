package rules

var FlyIOAccessTokenRegex = generateUniqueTokenRegex(
	`(?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3})`, false)

func FlyIOAccessToken() *Rule {
	return &Rule{
		BaseRuleID:      "d2410346-1a57-45a0-94a3-67e185a7ac3a",
		RuleID:          "flyio-access-token",
		Description:     "Uncovered a Fly.io API key",
		Regex:           FlyIOAccessTokenRegex,
		Entropy:         4,
		Keywords:        []string{"fo1_", "fm1", "fm2_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
	}
}
