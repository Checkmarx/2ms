package ruledefine

var notionAPITokenRegex = generateUniqueTokenRegex(
	`ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3}`, false).String()

func Notion() *Rule {
	return &Rule{
		RuleID:          "c8e8d78f-1273-4cd3-a6b5-99735a73ad0f",
		Description:     "Notion API token",
		RuleName:        "notion-api-token",
		Regex:           notionAPITokenRegex,
		Entropy:         4,
		Keywords:        []string{"ntn_"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategorySaaS, RuleType: 4},
	}
}
