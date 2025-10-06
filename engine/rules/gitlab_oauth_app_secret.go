package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabOauthAppSecretRegex = regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`)

func GitlabOauthAppSecret() *NewRule {
	return &NewRule{
		BaseRuleID:      "cff13bea-53f4-46ec-adab-3e165d6a1207",
		RuleID:          "gitlab-oauth-app-secret",
		Description:     "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
		Regex:           GitlabOauthAppSecretRegex,
		Entropy:         3,
		Keywords:        []string{"gloas-"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
