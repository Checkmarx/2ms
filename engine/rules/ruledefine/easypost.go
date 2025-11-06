package ruledefine

import (
	"regexp"
)

var easypostRegex = regexp.MustCompile(`\bEZAK(?i)[a-z0-9]{54}\b`).String()

func EasyPost() *Rule {
	return &Rule{
		RuleID:          "9c1a5a60-cf70-4c91-b103-a5a480176984",
		Description:     "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.", //nolint:lll
		RuleName:        "Easypost-Api-Token",
		Regex:           easypostRegex,
		Entropy:         2,
		Keywords:        []string{"EZAK"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
	}
}
