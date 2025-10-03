package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var NotionAPITokenRegex = utils.GenerateUniqueTokenRegex(`ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`, false)

func Notion() *NewRule {
	return &NewRule{
		BaseRuleID:      "c8e8d78f-1273-4cd3-a6b5-99735a73ad0f",
		Description:     "Notion API token",
		RuleID:          "notion-api-token",
		Regex:           NotionAPITokenRegex,
		Entropy:         4,
		Keywords:        []string{"ntn_"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
