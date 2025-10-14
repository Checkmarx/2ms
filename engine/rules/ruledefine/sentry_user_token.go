package ruledefine

var SentryUserTokenRegex = generateUniqueTokenRegex(`sntryu_[a-f0-9]{64}`, false)

func SentryUserToken() *Rule {
	return &Rule{
		BaseRuleID:      "583058fd-a4f6-4279-8cb6-c4f60ef5e4a3",
		RuleID:          "sentry-user-token",
		Description:     "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.",
		Regex:           SentryUserTokenRegex,
		Entropy:         3.5,
		Keywords:        []string{"sntryu_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
