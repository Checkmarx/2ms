package ruledefine

var TwitterAccessTokenRegex = generateSemiGenericRegex([]string{"twitter"}, "[0-9]{15,25}-[a-zA-Z0-9]{20,40}", true)

func TwitterAccessToken() *Rule {
	return &Rule{
		BaseRuleID:      "70c63637-e82d-44f1-8743-4de98d603d22",
		Description:     "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
		RuleID:          "twitter-access-token",
		Regex:           TwitterAccessTokenRegex,
		Keywords:        []string{"twitter"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
