package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func GitlabPatRoutable() *config.Rule {
	return &config.Rule{
		RuleID:      "gitlab-pat-routable",
		Description: "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       regexp.MustCompile(`\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`),
		Entropy:     4,
		Keywords:    []string{"glpat-"},
	}
}

func GitlabRunnerAuthenticationTokenRoutable() *config.Rule {
	return &config.Rule{
		RuleID:      "gitlab-runner-authentication-token-routable",
		Description: "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.",
		Regex:       regexp.MustCompile(`\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`),
		Entropy:     4,
		Keywords:    []string{"glrt-"},
	}
}
