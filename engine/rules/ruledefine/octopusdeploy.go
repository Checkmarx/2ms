package ruledefine

var octopusDeployAPIKeyRegex = generateUniqueTokenRegex(`API-[A-Z0-9]{26}`, false).String()

func OctopusDeployApiKey() *Rule {
	return &Rule{
		RuleID:        "5ba42e41-6652-42db-b316-0870042b4605",
		Description:   "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
		RuleName:      "Octopus-Deploy-Api-Key",
		Regex:         octopusDeployAPIKeyRegex,
		Entropy:       3,
		Keywords:      []string{"api-"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryCICD,
		ScoreRuleType: 4,
	}
}
