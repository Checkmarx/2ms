package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabDeployTokenRegex = regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`)

func GitlabDeployToken() *Rule {
	return &Rule{
		BaseRuleID:      "8d1908c7-feb0-4b63-b2a6-1b0dd51badd4",
		Description:     "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
		RuleID:          "gitlab-deploy-token",
		Regex:           GitlabDeployTokenRegex,
		Entropy:         3,
		Keywords:        []string{"gldt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
