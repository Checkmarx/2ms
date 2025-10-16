package ruledefine

var twitterBearerTokenRegex = generateSemiGenericRegex([]string{"twitter"}, "A{22}[a-zA-Z0-9%]{80,100}", true)

func TwitterBearerToken() *Rule {
	return &Rule{
		BaseRuleID:      "5b479cdf-e759-4bd9-92c6-79f25c835fb0",
		Description:     "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.",
		RuleID:          "twitter-bearer-token",
		Regex:           twitterBearerTokenRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
