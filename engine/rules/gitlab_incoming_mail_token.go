package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabIncomingMailTokenRegex = regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`)

func GitlabIncomingMailToken() *Rule {
	return &Rule{
		BaseRuleID:      "b51479b3-6f0a-41f5-a846-67b59d356294",
		RuleID:          "gitlab-incoming-mail-token",
		Description:     "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
		Regex:           GitlabIncomingMailTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glimt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
