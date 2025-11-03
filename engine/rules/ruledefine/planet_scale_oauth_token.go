package ruledefine

var planetScaleOAuthTokenRegex = generateUniqueTokenRegex(`pscale_oauth_[\w=\.-]{32,64}`, false).String()

func PlanetScaleOAuthToken() *Rule {
	return &Rule{
		RuleID:      "ddba7a67-d2c6-437c-8281-0d4a2cf52abc",
		Description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
		RuleName:    "Planetscale-Oauth-Token",
		Regex:       planetScaleOAuthTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"pscale_oauth_",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
