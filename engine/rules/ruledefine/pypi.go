package ruledefine

import (
	"regexp"
)

var pyPiUploadTokenRegex = regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`).String()

func PyPiUploadToken() *Rule {
	return &Rule{
		RuleID:      "9a242991-bc9a-4c82-91cf-26e416b79fb1",
		Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
		RuleName:    "pypi-upload-token",
		Regex:       pyPiUploadTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"pypi-AgEIcHlwaS5vcmc",
		},
		Severity:        "High",
		Tags:            []string{TagUploadToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
