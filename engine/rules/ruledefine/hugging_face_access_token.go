package ruledefine

var huggingFaceAccessTokenRegex = generateUniqueTokenRegex("hf_(?i:[a-z]{34})", false).String()

func HuggingFaceAccessToken() *Rule {
	return &Rule{
		BaseRuleID:  "11294760-6cd1-45e6-add2-403ef8662969",
		RuleID:      "huggingface-access-token",
		Description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
		Regex:       huggingFaceAccessTokenRegex,
		Entropy:     2,
		Keywords: []string{
			"hf_",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
