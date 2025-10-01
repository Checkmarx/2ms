package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabFeatureFlagClientTokenRegex = regexp.MustCompile(`glffct-[0-9a-zA-Z_\-]{20}`)

func GitlabFeatureFlagClientToken() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-feature-flag-client-token",
		Description: "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
		Regex:       GitlabFeatureFlagClientTokenRegex,
		Entropy:     3,
		Keywords:    []string{"glffct-"},
	}
}
