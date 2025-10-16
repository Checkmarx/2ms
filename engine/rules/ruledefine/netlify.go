package ruledefine

var netlifyAccessTokenRegex = generateSemiGenericRegex([]string{"netlify"},
	AlphaNumericExtended("40,46"), true)

func NetlifyAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "c23decf4-9f16-4ec6-8481-b3423f12ed4c",
		Description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
		RuleID:      "netlify-access-token",
		Regex:       netlifyAccessTokenRegex,
		Keywords: []string{
			"netlify",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryWebHostingAndDeployment, RuleType: 4},
	}
}
