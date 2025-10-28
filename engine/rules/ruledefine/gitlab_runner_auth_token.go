package ruledefine

import (
	"regexp"
)

var gitlabRunnerAuthenticationTokenRegex = regexp.MustCompile(`glrt-[0-9a-zA-Z_\-]{20}`).String()

func GitlabRunnerAuthenticationToken() *Rule {
	return &Rule{
		RuleID:          "a08764b1-3289-4a79-95b3-579a096fcc0c",
		RuleName:        "gitlab-runner-authentication-token",
		Description:     "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:           gitlabRunnerAuthenticationTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glrt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
