package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabOauthAppSecretRegex = regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`)

func GitlabOauthAppSecret() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-oauth-app-secret",
		Description: "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
		Regex:       GitlabOauthAppSecretRegex,
		Entropy:     3,
		Keywords:    []string{"gloas-"},
	}
}
