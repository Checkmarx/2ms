package ruledefine

import (
	"regexp"
)

var easypostTestAPITokenRegex = regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}\b`).String()

func EasyPostTestAPI() *Rule {
	return &Rule{
		RuleID:        "e0df7fdd-0109-477f-875d-b3dc89c1f71f",
		Description:   "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
		RuleName:      "Easypost-Test-Api-Token",
		Regex:         easypostTestAPITokenRegex,
		Entropy:       2,
		Keywords:      []string{"EZTK"},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryShipping,
		ScoreRuleType: 4,
	}
}
