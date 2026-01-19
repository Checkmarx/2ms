package ruledefine

var gitterAccessTokenRegex = generateSemiGenericRegex([]string{"gitter"},
	AlphaNumericExtendedShort("40"), true).String()

func GitterAccessToken() *Rule {
	return &Rule{
		RuleID:      "3b70b51e-5d70-485b-bf23-6b96cbda7133",
		Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
		RuleName:    "Gitter-Access-Token",
		Regex:       gitterAccessTokenRegex,
		Keywords: []string{
			"gitter",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
