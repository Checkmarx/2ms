package ruledefine

var twitterAccessTokenRegex = generateSemiGenericRegex(
	[]string{"twitter"}, "[0-9]{15,25}-[a-zA-Z0-9]{20,40}", true).String()

func TwitterAccessToken() *Rule {
	return &Rule{
		RuleID:        "70c63637-e82d-44f1-8743-4de98d603d22",
		Description:   "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
		RuleName:      "Twitter-Access-Token",
		Regex:         twitterAccessTokenRegex,
		Keywords:      []string{"twitter"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySocialMedia,
		ScoreRuleType: 4,
	}
}
