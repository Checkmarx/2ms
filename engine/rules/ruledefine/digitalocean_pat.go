package ruledefine

var digitaloceanPatRegex = generateUniqueTokenRegex(`dop_v1_[a-f0-9]{64}`, false).String()

func DigitalOceanPAT() *Rule {
	return &Rule{
		RuleID:          "5eb6a466-2bde-4aa4-b4d7-29b3eac6a11d",
		Description:     "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
		RuleName:        "Digitalocean-Pat",
		Regex:           digitaloceanPatRegex,
		Entropy:         3,
		Keywords:        []string{"dop_v1_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCloudPlatform, RuleType: 4},
	}
}
