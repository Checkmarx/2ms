package rules

import (
	"regexp"
)

var EasypostTestAPITokenRegex = regexp.MustCompile(`\bEZTK(?i)[a-z0-9]{54}\b`)

func EasyPostTestAPI() *NewRule {
	return &NewRule{
		Description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
		RuleID:      "easypost-test-api-token",
		Regex:       EasypostTestAPITokenRegex,
		Entropy:     2,
		Keywords:    []string{"EZTK"},
	}
}
