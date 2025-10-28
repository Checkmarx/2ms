package ruledefine

var linkedinClientSecretRegex = generateSemiGenericRegex([]string{
	"linked[_-]?in",
}, AlphaNumeric("16"), true).String()

func LinkedinClientSecret() *Rule {
	return &Rule{
		RuleID:      "266e5b15-aa39-4e8f-b7f4-6ce98a624d6a",
		Description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
		RuleName:    "linkedin-client-secret",
		Regex:       linkedinClientSecretRegex,
		Entropy:     2,
		Keywords: []string{
			"linkedin",
			"linked_in",
			"linked-in",
		},
		Severity:        "High",
		Tags:            []string{TagClientSecret},
		ScoreParameters: ScoreParameters{Category: CategorySocialMedia, RuleType: 4},
	}
}
