package rules

var PlanetScaleOAuthTokenRegex = generateUniqueTokenRegex(`pscale_oauth_[\w=\.-]{32,64}`, false)

func PlanetScaleOAuthToken() *Rule {
	return &Rule{
		BaseRuleID:  "ddba7a67-d2c6-437c-8281-0d4a2cf52abc",
		Description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
		RuleID:      "planetscale-oauth-token",
		Regex:       PlanetScaleOAuthTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"pscale_oauth_",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryDatabaseAsAService, RuleType: 4},
	}
}
