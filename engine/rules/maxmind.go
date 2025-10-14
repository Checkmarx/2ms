package rules

var MaxmindLicenseKeyRegex = generateUniqueTokenRegex(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`, false)

func MaxMindLicenseKey() *Rule {
	return &Rule{
		BaseRuleID:      "f39f3417-fa72-4f3b-a570-29523dc2a72b",
		Description:     "Discovered a potential MaxMind license key.",
		RuleID:          "maxmind-license-key",
		Regex:           MaxmindLicenseKeyRegex,
		Entropy:         4,
		Keywords:        []string{"_mmk"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryDataAnalytics, RuleType: 4},
	}
}
