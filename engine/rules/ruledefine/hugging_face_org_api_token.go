package ruledefine

var huggingFaceOrganizationApiTokenRegex = generateUniqueTokenRegex(
	"api_org_(?i:[a-z]{34})", false).String()

func HuggingFaceOrganizationApiToken() *Rule {
	return &Rule{
		RuleID:      "b2e67a8e-ec58-41b6-baf0-2a6b9b3de237",
		RuleName:    "Huggingface-Organization-Api-Token",
		Description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
		Regex:       huggingFaceOrganizationApiTokenRegex,

		Entropy: 2,
		Keywords: []string{
			"api_org_",
		},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryAIAndMachineLearning,
		ScoreRuleType: 4,
	}
}
