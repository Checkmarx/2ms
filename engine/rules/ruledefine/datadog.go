package ruledefine

var catadogAccessTokenRegex = generateSemiGenericRegex([]string{"datadog"},
	AlphaNumeric("40"), true).String()

func DatadogtokenAccessToken() *Rule {
	return &Rule{
		RuleID:      "f0967e3a-826e-4abd-9271-bc7db50d168d",
		Description: "Detected a Datadog Access Token, potentially risking monitoring and analytics data exposure and manipulation.",
		RuleName:    "Datadog-Access-Token",
		Regex:       catadogAccessTokenRegex,

		Keywords: []string{
			"datadog",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken, TagClientId},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
