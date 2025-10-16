package ruledefine

var settlemintServiceAccessTokenRegex = generateUniqueTokenRegex(`sm_sat_[a-zA-Z0-9]{16}`, false)

func SettlemintServiceAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "acb848b7-390a-4c7d-831a-300a3f76ad79",
		Description: "Found a Settlemint Service Access Token.",
		RuleID:      "settlemint-service-access-token",
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
