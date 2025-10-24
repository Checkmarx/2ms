package ruledefine

var facebookPageAccessTokenRegex = generateUniqueTokenRegex(
	"EAA[MC](?i)[a-z0-9]{100,}", false).String()

func FacebookPageAccessToken() *Rule {
	return &Rule{
		RuleID:          "aa0c13ec-cd3f-43a1-806f-05006e342946",
		Description:     "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.", //nolint:lll
		RuleName:        "facebook-page-access-token",
		Regex:           facebookPageAccessTokenRegex,
		Entropy:         4,
		Keywords:        []string{"EAAM", "EAAC"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
