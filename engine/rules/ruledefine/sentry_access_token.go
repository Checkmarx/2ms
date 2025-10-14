package ruledefine

var SentryAccessTokenRegex = generateSemiGenericRegex([]string{"sentry"}, Hex("64"), true)

func SentryAccessToken() *Rule {
	return &Rule{
		BaseRuleID: "ba2a5820-8dfd-4af5-9406-88d6b4c7144e",
		RuleID:     "sentry-access-token",
		Description: "Found a Sentry.io Access Token (old format)," +
			" risking unauthorized access to error tracking services and sensitive application data.",
		Regex:   SentryAccessTokenRegex,
		Entropy: 3,
		Keywords: []string{
			"sentry",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
