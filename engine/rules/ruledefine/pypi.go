package ruledefine

import (
	"regexp"
)

var PyPiUploadTokenRegex = regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`)

func PyPiUploadToken() *Rule {
	return &Rule{
		BaseRuleID:  "9a242991-bc9a-4c82-91cf-26e416b79fb1",
		Description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
		RuleID:      "pypi-upload-token",
		Regex:       PyPiUploadTokenRegex,
		Entropy:     3,
		Keywords: []string{
			"pypi-AgEIcHlwaS5vcmc",
		},
		Severity:        "High",
		Tags:            []string{TagUploadToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
