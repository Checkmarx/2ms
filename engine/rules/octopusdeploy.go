package rules

var OctopusDeployAPIKeyRegex = generateUniqueTokenRegex(`API-[A-Z0-9]{26}`, false)

func OctopusDeployApiKey() *Rule {
	return &Rule{
		BaseRuleID:      "5ba42e41-6652-42db-b316-0870042b4605",
		Description:     "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
		RuleID:          "octopus-deploy-api-key",
		Regex:           OctopusDeployAPIKeyRegex,
		Entropy:         3,
		Keywords:        []string{"api-"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
