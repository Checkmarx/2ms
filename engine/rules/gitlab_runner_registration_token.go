package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabRunnerRegistrationTokenRegex = regexp.MustCompile(`GR1348941[\w-]{20}`)

func GitlabRunnerRegistrationToken() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-rrt",
		Description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       GitlabRunnerRegistrationTokenRegex,
		Entropy:     3,
		Keywords:    []string{"GR1348941"},
	}
}
