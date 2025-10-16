package ruledefine

import (
	"regexp"
)

var gitlabScimTokenRegex = regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20}`)

func GitlabScimToken() *Rule {
	return &Rule{
		BaseRuleID:      "4c180ed4-6573-4b47-8b6d-94f2c9968ee8",
		RuleID:          "gitlab-scim-token",
		Description:     "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
		Regex:           gitlabScimTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glsoat-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
