package ruledefine

var scalingoAPITokenRegex = generateUniqueTokenRegex(`tk-us-[\w-]{48}`, false).String()

func ScalingoAPIToken() *Rule {
	return &Rule{
		RuleID:        "6206ffe0-227a-41f6-9805-b82d7281cd87",
		Description:   "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
		RuleName:      "Scalingo-Api-Token",
		Regex:         scalingoAPITokenRegex,
		Entropy:       2,
		Keywords:      []string{"tk-us-"},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryWebHostingAndDeployment,
		ScoreRuleType: 4,
	}
}
