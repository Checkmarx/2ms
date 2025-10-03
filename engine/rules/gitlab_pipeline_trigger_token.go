package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabPipelineTriggerTokenRegex = regexp.MustCompile(`glptt-[0-9a-f]{40}`)

func GitlabPipelineTriggerToken() *NewRule {
	return &NewRule{
		RuleID:          "gitlab-ptt",
		Description:     "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
		Regex:           GitlabPipelineTriggerTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glptt-"},
		Tags:            []string{TagTriggerToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
