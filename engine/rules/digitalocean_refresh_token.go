package rules

var DigitaloceanRefreshTokenRegex = generateUniqueTokenRegex(`dor_v1_[a-f0-9]{64}`, true)

func DigitalOceanRefreshToken() *Rule {
	return &Rule{
		BaseRuleID:      "38567389-ffda-4c25-b717-486b945027c4",
		Description:     "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.", //nolint:lll
		RuleID:          "digitalocean-refresh-token",
		Regex:           DigitaloceanRefreshTokenRegex,
		Keywords:        []string{"dor_v1_"},
		Severity:        "High",
		Tags:            []string{TagRefreshToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
