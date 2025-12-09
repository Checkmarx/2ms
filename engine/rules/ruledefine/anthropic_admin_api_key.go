package ruledefine

var anthropicAdminApiKeyRegex = generateUniqueTokenRegex(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`, false).String()

func AnthropicAdminApiKey() *Rule {
	return &Rule{
		RuleID: "4d6ff5a0-5ab4-430a-9ca9-404b675e6db2",
		Description: "Detected an Anthropic Admin API Key," +
			" risking unauthorized access to administrative functions and sensitive AI model configurations.",
		RuleName:      "Anthropic-Admin-Api-Key",
		Regex:         anthropicAdminApiKeyRegex,
		Keywords:      []string{"sk-ant-admin01"},
		Severity:      "High",
		Tags:          []string{TagApiKey},
		Category:      CategoryAIAndMachineLearning,
		ScoreRuleType: 4,
	}
}
