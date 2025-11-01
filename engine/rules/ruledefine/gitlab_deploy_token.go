package ruledefine

import (
	"regexp"
)

var gitlabDeployTokenRegex = regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`).String()

func GitlabDeployToken() *Rule {
	return &Rule{
		RuleID:          "8d1908c7-feb0-4b63-b2a6-1b0dd51badd4",
		Description:     "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
		RuleName:        "Gitlab-Deploy-Token",
		Regex:           gitlabDeployTokenRegex,
		Entropy:         3,
		Keywords:        []string{"gldt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
