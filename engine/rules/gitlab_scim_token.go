package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabScimTokenRegex = regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20}`)

func GitlabScimToken() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-scim-token",
		Description: "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
		Regex:       GitlabScimTokenRegex,
		Entropy:     3,
		Keywords:    []string{"glsoat-"},
	}
}
