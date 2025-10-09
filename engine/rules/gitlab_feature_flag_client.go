package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabFeatureFlagClientTokenRegex = regexp.MustCompile(`glffct-[0-9a-zA-Z_\-]{20}`)

func GitlabFeatureFlagClientToken() *Rule {
	return &Rule{
		BaseRuleID:      "050239ad-8c7f-4df4-bf07-58f304c2bcb4",
		RuleID:          "gitlab-feature-flag-client-token",
		Description:     "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
		Regex:           GitlabFeatureFlagClientTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glffct-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
