package ruledefine

var npmAccessTokenRegex = generateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true).String()

func NPM() *Rule {
	return &Rule{
		RuleID:      "c95ab734-0263-4b08-9366-1407667f32e2",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		RuleName:    "Npm-Access-Token",
		Regex:       npmAccessTokenRegex,
		Entropy:     2,
		Keywords: []string{
			"npm_",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryPackageManagement,
		ScoreRuleType: 4,
	}
}
