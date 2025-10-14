package rules

var ReadMeRegex = generateUniqueTokenRegex(`rdme_[a-z0-9]{70}`, false)

func ReadMe() *Rule {
	return &Rule{
		BaseRuleID:  "20784aca-b7f1-4657-8314-789b08f591bc",
		Description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
		RuleID:      "readme-api-token",
		Regex:       ReadMeRegex,
		Entropy:     2,
		Keywords: []string{
			"rdme_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAPIAccess, RuleType: 4},
	}
}
