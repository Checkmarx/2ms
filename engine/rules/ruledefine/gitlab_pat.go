package ruledefine

import (
	"regexp"
)

var gitlabPatRegex = regexp.MustCompile(`glpat-[\w-]{20}`).String()

func GitlabPat() *Rule {
	return &Rule{
		RuleID:          "d641ed7c-e79f-4ce6-bbce-c5de97df7752",
		RuleName:        "gitlab-pat",
		Description:     "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:           gitlabPatRegex,
		Entropy:         3,
		Keywords:        []string{"glpat-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
