package ruledefine

var grafanaCloudAPITokenRegex = generateUniqueTokenRegex(`glc_[A-Za-z0-9+/]{32,400}={0,3}`, true).String()

func GrafanaCloudApiToken() *Rule {
	return &Rule{
		RuleID:          "c8400ab6-4fad-4a12-8ded-02b3151f6eb2",
		Description:     "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.",
		RuleName:        "Grafana-Cloud-Api-Token",
		Regex:           grafanaCloudAPITokenRegex,
		Entropy:         3,
		Keywords:        []string{"glc_"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
