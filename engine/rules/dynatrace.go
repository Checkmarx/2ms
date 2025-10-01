package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var DynatraceAPITokenRegex = regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`)

func DynatraceAPIToken() *NewRule {
	return &NewRule{
		Description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
		RuleID:      "dynatrace-api-token",
		Regex:       DynatraceAPITokenRegex,
		Entropy:     4,
		Keywords:    []string{"dt0c01."},
	}
}
