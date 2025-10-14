package ruledefine

var GitterAccessTokenRegex = generateSemiGenericRegex([]string{"gitter"},
	AlphaNumericExtendedShort("40"), true)

func GitterAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "3b70b51e-5d70-485b-bf23-6b96cbda7133",
		Description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
		RuleID:      "gitter-access-token",
		Regex:       GitterAccessTokenRegex,
		Keywords: []string{
			"gitter",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
