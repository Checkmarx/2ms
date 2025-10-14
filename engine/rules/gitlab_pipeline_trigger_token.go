package rules

import (
	"regexp"
)

var GitlabPipelineTriggerTokenRegex = regexp.MustCompile(`glptt-[0-9a-f]{40}`)

func GitlabPipelineTriggerToken() *Rule {
	return &Rule{
		BaseRuleID:      "3dbfeba1-1c7e-4f0c-a0fe-62ae08b4b34c",
		RuleID:          "gitlab-ptt",
		Description:     "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:           GitlabPipelineTriggerTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glptt-"},
		Severity:        "High",
		Tags:            []string{TagTriggerToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
