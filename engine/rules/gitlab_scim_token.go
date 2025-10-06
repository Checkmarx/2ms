package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabScimTokenRegex = regexp.MustCompile(`glsoat-[0-9a-zA-Z_\-]{20}`)

func GitlabScimToken() *NewRule {
	return &NewRule{
		BaseRuleID:      "4c180ed4-6573-4b47-8b6d-94f2c9968ee8",
		RuleID:          "gitlab-scim-token",
		Description:     "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
		Regex:           GitlabScimTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glsoat-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
