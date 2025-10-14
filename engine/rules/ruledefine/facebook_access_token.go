package ruledefine

var FacebookAccessTokenRegex = generateUniqueTokenRegex(`\d{15,16}(\||%)[0-9a-z\-_]{27,40}`, true)

func FacebookAccessToken() *Rule {
	return &Rule{
		BaseRuleID: "1aebe1a9-8fab-4d00-a42d-0a1014769b73",
		Description: "Discovered a Facebook Access Token," +
			" posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleID:          "facebook-access-token",
		Regex:           FacebookAccessTokenRegex,
		Entropy:         3,
		Keywords:        []string{"facebook"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
