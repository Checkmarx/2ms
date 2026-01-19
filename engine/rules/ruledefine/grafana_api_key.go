package ruledefine

var grafanaAPIKeyRegex = generateUniqueTokenRegex(`eyJrIjoi[A-Za-z0-9]{70,400}={0,3}`, true).String()

func GrafanaApiKey() *Rule {
	return &Rule{
		RuleID:        "61b7855c-6d6a-4067-b477-d0d26c3e1448",
		Description:   "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
		RuleName:      "Grafana-Api-Key",
		Regex:         grafanaAPIKeyRegex,
		Entropy:       3,
		Keywords:      []string{"eyJrIjoi"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryApplicationMonitoring,
		ScoreRuleType: 4,
	}
}
