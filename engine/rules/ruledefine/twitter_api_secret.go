package ruledefine

var twitterAPISecretRegex = generateSemiGenericRegex([]string{"twitter"}, AlphaNumeric("50"), true).String()

func TwitterAPISecret() *Rule {
	return &Rule{
		RuleID:        "d1d00b76-8fa2-4276-8f1f-43440a2d2777",
		Description:   "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
		RuleName:      "Twitter-Api-Secret",
		Regex:         twitterAPISecretRegex,
		Keywords:      []string{"twitter"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
