package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var HuggingFaceOrganizationApiTokenRegex = utils.GenerateUniqueTokenRegex("api_org_(?i:[a-z]{34})", false)

func HuggingFaceOrganizationApiToken() *NewRule {
	return &NewRule{
		BaseRuleID:  "b2e67a8e-ec58-41b6-baf0-2a6b9b3de237",
		RuleID:      "huggingface-organization-api-token",
		Description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
		Regex:       HuggingFaceOrganizationApiTokenRegex,

		Entropy: 2,
		Keywords: []string{
			"api_org_",
		},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryAIAndMachineLearning, RuleType: 4},
	}
}
