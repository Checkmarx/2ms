package ruledefine

var grafanaServiceAccountTokenRegex = generateUniqueTokenRegex(`glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`, true).String()

func GrafanaServiceAccountToken() *Rule {
	return &Rule{
		RuleID:          "60b6a2aa-2eaf-4a3d-bd3c-6d5f6274b4fc",
		Description:     "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
		RuleName:        "grafana-service-account-token",
		Regex:           grafanaServiceAccountTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glsa_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
