package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabRunnerAuthenticationTokenRegex = regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`)

func GitlabRunnerAuthenticationToken() *NewRule {
	return &NewRule{
		RuleID:          "gitlab-runner-authentication-token",
		Description:     "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:           GitlabRunnerAuthenticationTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glrt-"},
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
