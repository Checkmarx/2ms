package ruledefine

var oktaAccessTokenRegex = generateSemiGenericRegex(
	[]string{`(?-i:[Oo]kta|OKTA)`}, `00[\w=\-]{40}`, false).String()

func OktaAccessToken() *Rule {
	return &Rule{
		RuleID:      "34da24ff-cea1-48c2-bf4f-1f898a662464",
		Description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
		RuleName:    "okta-access-token",
		Regex:       oktaAccessTokenRegex,
		Entropy:     4,
		Keywords: []string{
			"okta",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
