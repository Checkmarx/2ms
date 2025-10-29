package ruledefine

var twitterAccessSecretRegex = generateSemiGenericRegex([]string{"twitter"}, AlphaNumeric("45"), true).String()

func TwitterAccessSecret() *Rule {
	return &Rule{
		RuleID:          "ff86e24f-7ee8-4a9e-8107-f9e26f354247",
		Description:     "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
		RuleName:        "Twitter-Access-Secret",
		Regex:           twitterAccessSecretRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagPublicSecret},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
