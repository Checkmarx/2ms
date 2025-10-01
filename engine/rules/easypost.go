package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var EasypostRegex = regexp.MustCompile(`\bEZAK(?i)[a-z0-9]{54}\b`)

func Easypost() *NewRule {
	return &NewRule{
		Description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
		RuleID:      "easypost-api-token",
		Regex:       EasypostRegex,
		Entropy:     2,
		Keywords:    []string{"EZAK"},
	}
}
