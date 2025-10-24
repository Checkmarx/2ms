package ruledefine

var facebookAccessTokenRegex = generateUniqueTokenRegex(
	`\d{15,16}(\||%)[0-9a-z\-_]{27,40}`, true).String()

func FacebookAccessToken() *Rule {
	return &Rule{
		RuleID: "1aebe1a9-8fab-4d00-a42d-0a1014769b73",
		Description: "Discovered a Facebook Access Token," +
			" posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
		RuleName:        "facebook-access-token",
		Regex:           facebookAccessTokenRegex,
		Entropy:         3,
		Keywords:        []string{"facebook"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
