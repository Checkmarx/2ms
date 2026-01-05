package ruledefine

var digitaloceanRefreshTokenRegex = generateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`, true).String()

func DigitalOceanRefreshToken() *Rule {
	return &Rule{
		RuleID:        "38567389-ffda-4c25-b717-486b945027c4",
		Description:   "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.", //nolint:lll
		RuleName:      "Digitalocean-Refresh-Token",
		Regex:         digitaloceanRefreshTokenRegex,
		Keywords:      []string{"dor_v1_"},
		Severity:      "High",
		Tags:          []string{TagRefreshToken},
		Category:      CategoryAPIAccess,
		ScoreRuleType: 4,
	}
}
