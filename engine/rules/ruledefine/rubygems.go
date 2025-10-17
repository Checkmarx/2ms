package ruledefine

var rubyGemsAPITokenRegex = generateUniqueTokenRegex(`rubygems_[a-f0-9]{48}`, false).String()

func RubyGemsAPIToken() *Rule {
	return &Rule{
		BaseRuleID:  "33139118-434f-4e93-99fd-630243e94d93",
		Description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
		RuleID:      "rubygems-api-token",
		Regex:       rubyGemsAPITokenRegex,
		Entropy:     2,
		Keywords: []string{
			"rubygems_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
