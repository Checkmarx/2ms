package ruledefine

var sidekiqSecretRegex = generateSemiGenericRegex([]string{"BUNDLE_ENTERPRISE__CONTRIBSYS__COM", "BUNDLE_GEMS__CONTRIBSYS__COM"},
	`[a-f0-9]{8}:[a-f0-9]{8}`, true).String()

func SidekiqSecret() *Rule {
	return &Rule{
		BaseRuleID:      "568ac40e-7140-4e1d-b7ab-fa28148ede2e",
		Description:     "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.",
		RuleID:          "sidekiq-secret",
		Regex:           sidekiqSecretRegex,
		Keywords:        []string{"BUNDLE_ENTERPRISE__CONTRIBSYS__COM", "BUNDLE_GEMS__CONTRIBSYS__COM"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryBackgroundProcessingService, RuleType: 4},
	}
}
