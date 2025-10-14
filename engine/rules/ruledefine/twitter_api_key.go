package ruledefine

var TwitterAPIKeyRegex = generateSemiGenericRegex([]string{"twitter"}, AlphaNumeric("25"), true)

func TwitterAPIKey() *Rule {
	return &Rule{
		BaseRuleID:      "92c1a521-9332-488c-b323-b70a280c499f",
		Description:     "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
		RuleID:          "twitter-api-key",
		Regex:           TwitterAPIKeyRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
