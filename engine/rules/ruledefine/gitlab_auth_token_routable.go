package ruledefine

import (
	"regexp"
)

var gitlabRunnerAuthenticationTokenRoutableRegex = regexp.MustCompile(
	`\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`).String()

func GitlabRunnerAuthenticationTokenRoutable() *Rule {
	return &Rule{
		BaseRuleID:      "a473b392-cd0e-4f15-adcf-ce1080919b10",
		RuleID:          "gitlab-runner-authentication-token-routable",
		Description:     "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.", //nolint:lll
		Regex:           gitlabRunnerAuthenticationTokenRoutableRegex,
		Entropy:         4,
		Keywords:        []string{"glrt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
