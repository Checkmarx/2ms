package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabDeployTokenRegex = regexp.MustCompile(`gldt-[0-9a-zA-Z_\-]{20}`)

func GitlabDeployToken() *NewRule {
	return &NewRule{
		Description: "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
		RuleID:      "gitlab-deploy-token",
		Regex:       GitlabDeployTokenRegex,
		Entropy:     3,
		Keywords:    []string{"gldt-"},
	}
}
