package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var CohereApiTokenRegex = utils.GenerateSemiGenericRegex([]string{"cohere", "CO_API_KEY"}, `[a-zA-Z0-9]{40}`, false)

func CohereAPIToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "8f7f550e-8c76-423f-996c-e655662a42ac",
		Description: "Identified a Cohere Token, posing a risk of unauthorized access to AI services and data manipulation.",
		RuleID:      "cohere-api-token",
		Regex:       CohereApiTokenRegex,
		Entropy:     4,
		Keywords: []string{
			"cohere",
			"CO_API_KEY",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
