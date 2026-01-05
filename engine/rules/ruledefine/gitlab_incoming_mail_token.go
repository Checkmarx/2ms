package ruledefine

import (
	"regexp"
)

var gitlabIncomingMailTokenRegex = regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`).String()

func GitlabIncomingMailToken() *Rule {
	return &Rule{
		RuleID:        "b51479b3-6f0a-41f5-a846-67b59d356294",
		RuleName:      "Gitlab-Incoming-Mail-Token",
		Description:   "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
		Regex:         gitlabIncomingMailTokenRegex,
		Entropy:       3,
		Keywords:      []string{"glimt-"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySourceCodeManagement,
		ScoreRuleType: 4,
	}
}
