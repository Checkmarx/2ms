package rules

import (
	"regexp"
)

var GitlabRunnerRegistrationTokenRegex = regexp.MustCompile(`GR1348941[\w-]{20}`)

func GitlabRunnerRegistrationToken() *Rule {
	return &Rule{
		BaseRuleID:      "37c885be-0d68-44b3-9b53-8fa633676077",
		RuleID:          "gitlab-rrt",
		Description:     "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:           GitlabRunnerRegistrationTokenRegex,
		Entropy:         3,
		Keywords:        []string{"GR1348941"},
		Severity:        "High",
		Tags:            []string{TagRegistrationToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
