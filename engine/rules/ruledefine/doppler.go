package ruledefine

import (
	"regexp"
)

var dopplerAPITokenRegex = regexp.MustCompile(`dp\.pt\.(?i)[a-z0-9]{43}`).String()

func Doppler() *Rule {
	return &Rule{
		BaseRuleID:      "d5b89e2d-cba5-4551-85db-cef2294274f1",
		Description:     "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
		RuleID:          "doppler-api-token",
		Regex:           dopplerAPITokenRegex,
		Entropy:         2,
		Keywords:        []string{`dp.pt.`},
		Severity:        "High",
		Tags:            []string{TagApiToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
