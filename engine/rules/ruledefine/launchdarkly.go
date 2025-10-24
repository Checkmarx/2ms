package ruledefine

var launchdarklyAccessTokenRegex = generateSemiGenericRegex(
	[]string{"launchdarkly"}, AlphaNumericExtended("40"), true).String()

func LaunchDarklyAccessToken() *Rule {
	return &Rule{
		RuleID:      "f39021e6-f765-4d39-8fc5-2d6113b89a09",
		Description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
		RuleName:    "launchdarkly-access-token",
		Regex:       launchdarklyAccessTokenRegex,
		Keywords: []string{
			"launchdarkly",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
	}
}
