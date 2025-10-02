package rules

import (
	"regexp"
)

var EasypostTestAPITokenRegex = regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}\b`)

func EasyPostTestAPI() *NewRule {
	return &NewRule{
		BaseRuleID:      "e0df7fdd-0109-477f-875d-b3dc89c1f71f",
		Description:     "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
		RuleID:          "easypost-test-api-token",
		Regex:           EasypostTestAPITokenRegex,
		Entropy:         2,
		Keywords:        []string{"EZTK"},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryShipping, RuleType: 4},
	}
}
