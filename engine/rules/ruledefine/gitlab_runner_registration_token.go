package ruledefine

import (
	"regexp"
)

var gitlabRunnerRegistrationTokenRegex = regexp.MustCompile(`GR1348941[\w-]{20}`).String()

func GitlabRunnerRegistrationToken() *Rule {
	return &Rule{
		RuleID:          "37c885be-0d68-44b3-9b53-8fa633676077",
		RuleName:        "Gitlab-Rrt",
		Description:     "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:           gitlabRunnerRegistrationTokenRegex,
		Entropy:         3,
		Keywords:        []string{"GR1348941"},
		Severity:        "High",
		Tags:            []string{TagRegistrationToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
