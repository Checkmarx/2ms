package ruledefine

var settlemintPersonalAccessTokenRegex = generateUniqueTokenRegex(`sm_pat_[a-zA-Z0-9]{16}`, false).String()

func SettlemintPersonalAccessToken() *Rule {
	return &Rule{
		RuleID:      "7391f3bc-e15b-4f9b-af1d-e355c4cd65c3",
		Description: "Found a Settlemint Personal Access Token.",
		RuleName:    "settlemint-personal-access-token",
		Regex:       settlemintPersonalAccessTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"sm_pat",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySoftwareDevelopment, RuleType: 4},
	}
}
