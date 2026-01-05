package ruledefine

var settlemintApplicationAccessTokenRegex = generateUniqueTokenRegex(
	`sm_aat_[a-zA-Z0-9]{16}`, false).String()

func SettlemintApplicationAccessToken() *Rule {
	return &Rule{
		RuleID:      "ee89d8a5-42bd-47f1-ab61-79dd59196d1d",
		Description: "Found a Settlemint Application Access Token.",
		RuleName:    "Settlemint-Application-Access-Token",
		Regex:       settlemintApplicationAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"sm_aat",
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySoftwareDevelopment,
		ScoreRuleType: 4,
	}
}
