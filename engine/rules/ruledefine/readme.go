package ruledefine

var readMeRegex = generateUniqueTokenRegex(`rdme_[a-z0-9]{70}`, false).String()

func ReadMe() *Rule {
	return &Rule{
		RuleID:      "20784aca-b7f1-4657-8314-789b08f591bc",
		Description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
		RuleName:    "readme-api-token",
		Regex:       readMeRegex,
		Entropy:     2,
		Keywords: []string{
			"rdme_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
