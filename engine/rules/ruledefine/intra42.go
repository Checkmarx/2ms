package ruledefine

var Intra42ClientSecretRegex = generateUniqueTokenRegex(`s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64}`, false)

func Intra42ClientSecret() *Rule {
	return &Rule{
		BaseRuleID:  "989afd3d-53ae-4d75-82e3-f537a4719d7c",
		Description: "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.",
		RuleID:      "intra42-client-secret",
		Regex:       Intra42ClientSecretRegex,
		Entropy:     3,
		Keywords: []string{
			"intra",
			"s-s4t2ud-",
			"s-s4t2af-",
		},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
	}
}
