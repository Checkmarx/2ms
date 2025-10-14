package rules

var AnthropicAdminApiKeyRegex = generateUniqueTokenRegex(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`, false)

func AnthropicAdminApiKey() *Rule {
	return &Rule{
		BaseRuleID: "4d6ff5a0-5ab4-430a-9ca9-404b675e6db2",
		Description: "Detected an Anthropic Admin API Key," +
			" risking unauthorized access to administrative functions and sensitive AI model configurations.",
		RuleID:          "anthropic-admin-api-key",
		Regex:           AnthropicAdminApiKeyRegex,
		Keywords:        []string{"sk-ant-admin01"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
