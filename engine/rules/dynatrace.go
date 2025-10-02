package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var DynatraceAPITokenRegex = regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`)

func Dynatrace() *NewRule {
	return &NewRule{
		BaseRuleID:      "469da8fd-e2cc-4ccc-bc23-1702064b9b66",
		Description:     "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
		RuleID:          "dynatrace-api-token",
		Regex:           DynatraceAPITokenRegex,
		Entropy:         4,
		Keywords:        []string{"dt0c01."},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryApplicationMonitoring, RuleType: 4},
	}
}
