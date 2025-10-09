package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var PrivateAITokenRegex = utils.GenerateSemiGenericRegex([]string{"private[_-]?ai"}, `[a-z0-9]{32}`, false)

func PrivateAIToken() *Rule {
	return &Rule{
		BaseRuleID:  "43bf9a5d-7994-4fc5-a9d7-4277340314a4",
		Description: "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
		RuleID:      "privateai-api-token",
		Regex:       PrivateAITokenRegex,
		Entropy:     3,
		Keywords: []string{
			"privateai",
			"private_ai",
			"private-ai",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
