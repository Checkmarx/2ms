package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var OpenaiAPIKeyRegex = utils.GenerateUniqueTokenRegex(`sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`, false) //nolint:lll

func OpenAI() *Rule {
	return &Rule{
		BaseRuleID:  "9128fa83-3dfe-4e32-bf58-89d98d17a6a9",
		Description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
		RuleID:      "openai-api-key",
		Regex:       OpenaiAPIKeyRegex,
		Entropy:     3,
		Keywords: []string{
			"T3BlbkFJ",
		},
		Severity:        "High",
		Tags:            []string{TagApiKey},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
