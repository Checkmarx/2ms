package ruledefine

var sentryUserTokenRegex = generateUniqueTokenRegex(`sntryu_[a-f0-9]{64}`, false).String()

func SentryUserToken() *Rule {
	return &Rule{
		RuleID:        "583058fd-a4f6-4279-8cb6-c4f60ef5e4a3",
		RuleName:      "Sentry-User-Token",
		Description:   "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.",
		Regex:         sentryUserTokenRegex,
		Entropy:       3.5,
		Keywords:      []string{"sntryu_"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryApplicationMonitoring,
		ScoreRuleType: 4,
	}
}
