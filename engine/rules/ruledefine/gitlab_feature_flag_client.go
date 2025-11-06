package ruledefine

import (
	"regexp"
)

var gitlabFeatureFlagClientTokenRegex = regexp.MustCompile(`glffct-[0-9a-zA-Z_\-]{20}`).String()

func GitlabFeatureFlagClientToken() *Rule {
	return &Rule{
		RuleID:          "050239ad-8c7f-4df4-bf07-58f304c2bcb4",
		RuleName:        "Gitlab-Feature-Flag-Client-Token",
		Description:     "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
		Regex:           gitlabFeatureFlagClientTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glffct-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
