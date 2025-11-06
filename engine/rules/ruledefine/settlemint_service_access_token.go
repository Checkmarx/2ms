package ruledefine

var settlemintServiceAccessTokenRegex = generateUniqueTokenRegex(`sm_sat_[a-zA-Z0-9]{16}`, false).String()

func SettlemintServiceAccessToken() *Rule {
	return &Rule{
		RuleID:      "acb848b7-390a-4c7d-831a-300a3f76ad79",
		Description: "Found a Settlemint Service Access Token.",
		RuleName:    "Settlemint-Service-Access-Token",
		Regex:       settlemintServiceAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"sm_sat",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
	}
}
