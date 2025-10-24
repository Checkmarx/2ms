package ruledefine

var sentryAccessTokenRegex = generateSemiGenericRegex([]string{"sentry"}, Hex("64"), true).String()

func SentryAccessToken() *Rule {
	return &Rule{
		RuleID:   "ba2a5820-8dfd-4af5-9406-88d6b4c7144e",
		RuleName: "sentry-access-token",
		Description: "Found a Sentry.io Access Token (old format)," +
			" risking unauthorized access to error tracking services and sensitive application data.",
		Regex:   sentryAccessTokenRegex,
		Entropy: 3,
		Keywords: []string{
			"sentry",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
