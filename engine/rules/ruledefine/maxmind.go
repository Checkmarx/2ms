package ruledefine

var maxmindLicenseKeyRegex = generateUniqueTokenRegex(`[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk`, false).String()

func MaxMindLicenseKey() *Rule {
	return &Rule{
		RuleID:        "f39f3417-fa72-4f3b-a570-29523dc2a72b",
		Description:   "Discovered a potential MaxMind license key.",
		RuleName:      "Maxmind-License-Key",
		Regex:         maxmindLicenseKeyRegex,
		Entropy:       4,
		Keywords:      []string{"_mmk"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryDataAnalytics,
		ScoreRuleType: 4,
	}
}
