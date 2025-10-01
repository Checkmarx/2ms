package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabFeedTokenRegex = regexp.MustCompile(`glft-[0-9a-zA-Z_\-]{20}`)

func GitlabFeedToken() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-feed-token",
		Description: "Identified a GitLab feed token, risking exposure of user data.",
		Regex:       GitlabFeedTokenRegex,
		Entropy:     3,
		Keywords:    []string{"glft-"},
	}
}
