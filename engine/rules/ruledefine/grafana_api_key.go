package ruledefine

var GrafanaAPIKeyRegex = generateUniqueTokenRegex(`eyJrIjoi[A-Za-z0-9]{70,400}={0,3}`, true)

func GrafanaApiKey() *Rule {
	return &Rule{
		BaseRuleID:      "61b7855c-6d6a-4067-b477-d0d26c3e1448",
		Description:     "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
		RuleID:          "grafana-api-key",
		Regex:           GrafanaAPIKeyRegex,
		Entropy:         3,
		Keywords:        []string{"eyJrIjoi"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
