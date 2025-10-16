package ruledefine

var npmAccessTokenRegex = generateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true)

func NPM() *Rule {
	return &Rule{
		BaseRuleID:  "c95ab734-0263-4b08-9366-1407667f32e2",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		RuleID:      "npm-access-token",
		Regex:       npmAccessTokenRegex,
		Entropy:     2,
		Keywords: []string{
			"npm_",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
