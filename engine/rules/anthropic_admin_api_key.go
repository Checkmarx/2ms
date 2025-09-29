package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var AnthropicAdminApiKeyRegex = utils.GenerateUniqueTokenRegex(`sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA`, false)

func AnthropicAdminApiKey() *NewRule {
	return &NewRule{
		Description: "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
		RuleID:      "anthropic-admin-api-key",
		Regex:       AnthropicAdminApiKeyRegex,
		Keywords:    []string{"sk-ant-admin01"},
	}
}
