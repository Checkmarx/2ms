package ruledefine

var twitterAPIKeyRegex = generateSemiGenericRegex([]string{"twitter"}, AlphaNumeric("25"), true).String()

func TwitterAPIKey() *Rule {
	return &Rule{
		RuleID:        "92c1a521-9332-488c-b323-b70a280c499f",
		Description:   "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
		RuleName:      "Twitter-Api-Key",
		Regex:         twitterAPIKeyRegex,
		Keywords:      []string{"twitter"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
