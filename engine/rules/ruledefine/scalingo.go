package ruledefine

var ScalingoAPITokenRegex = generateUniqueTokenRegex(`tk-us-[\w-]{48}`, false)

func ScalingoAPIToken() *Rule {
	return &Rule{
		BaseRuleID:      "6206ffe0-227a-41f6-9805-b82d7281cd87",
		Description:     "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleID:          "scalingo-api-token",
		Regex:           ScalingoAPITokenRegex,
		Entropy:         2,
		Keywords:        []string{"tk-us-"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
	}
}
