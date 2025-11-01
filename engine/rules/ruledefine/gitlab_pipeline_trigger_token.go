package ruledefine

import (
	"regexp"
)

var gitlabPipelineTriggerTokenRegex = regexp.MustCompile(`glptt-[0-9a-f]{40}`).String()

func GitlabPipelineTriggerToken() *Rule {
	return &Rule{
		RuleID:          "3dbfeba1-1c7e-4f0c-a0fe-62ae08b4b34c",
		RuleName:        "Gitlab-Ptt",
		Description:     "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:           gitlabPipelineTriggerTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glptt-"},
		Severity:        "High",
		Tags:            []string{TagTriggerToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
