package rules

var CodecovAccessTokenRegex = generateSemiGenericRegex([]string{"codecov"}, AlphaNumeric("32"), true)

func CodecovAccessToken() *Rule {
	return &Rule{
		BaseRuleID: "1f19a116-2eeb-4a2b-b439-c1fe5c9d0959",
		Description: "Found a pattern resembling a Codecov Access Token," +
			" posing a risk of unauthorized access to code coverage reports and sensitive data.",
		RuleID: "codecov-access-token",
		Regex:  CodecovAccessTokenRegex,
		Keywords: []string{
			"codecov",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySecurity, RuleType: 4},
	}
}
