package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabIncomingMailTokenRegex = regexp.MustCompile(`glimt-[0-9a-zA-Z_\-]{25}`)

func GitlabIncomingMailToken() *NewRule {
	return &NewRule{
		RuleID:          "gitlab-incoming-mail-token",
		Description:     "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
		Regex:           GitlabIncomingMailTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glimt-"},
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
