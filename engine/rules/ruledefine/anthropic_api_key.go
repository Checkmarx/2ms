package ruledefine

var AnthropicApiKeyRegex = generateUniqueTokenRegex(`sk-ant-api03-[a-zA-Z0-9_\-]{93}AA`, false)

func AnthropicApiKey() *Rule {
	return &Rule{
		BaseRuleID: "ccb64199-5c77-4ab2-8beb-a88034fec55c",
		Description: "Identified an Anthropic API Key," +
			" which may compromise AI assistant integrations and expose sensitive data to unauthorized access.",
		RuleID:          "anthropic-api-key",
		Regex:           AnthropicApiKeyRegex,
		Keywords:        []string{"sk-ant-api03"},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
