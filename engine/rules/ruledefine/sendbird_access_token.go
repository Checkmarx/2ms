package ruledefine

var SendbirdAccessTokenRegex = generateSemiGenericRegex([]string{"sendbird"}, Hex("40"), true)

func SendbirdAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "fcf4ddb2-4a62-4a73-a664-4d8226c68a9f",
		Description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
		RuleID:      "sendbird-access-token",
		Regex:       SendbirdAccessTokenRegex,
		Keywords: []string{
			"sendbird",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
