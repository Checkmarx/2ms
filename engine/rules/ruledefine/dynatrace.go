package ruledefine

import (
	"regexp"
)

var dynatraceAPITokenRegex = regexp.MustCompile(`dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`).String()

func Dynatrace() *Rule {
	return &Rule{
		RuleID:        "469da8fd-e2cc-4ccc-bc23-1702064b9b66",
		Description:   "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
		RuleName:      "Dynatrace-Api-Token",
		Regex:         dynatraceAPITokenRegex,
		Entropy:       4,
		Keywords:      []string{"dt0c01."},
		Severity:      "High",
		Tags:          []string{TagApiToken},
		Category:      CategoryApplicationMonitoring,
		ScoreRuleType: 4,
	}
}
