package ruledefine

import (
	"regexp"
)

var gitlabOauthAppSecretRegex = regexp.MustCompile(`gloas-[0-9a-zA-Z_\-]{64}`).String()

func GitlabOauthAppSecret() *Rule {
	return &Rule{
		RuleID:        "cff13bea-53f4-46ec-adab-3e165d6a1207",
		RuleName:      "Gitlab-Oauth-App-Secret",
		Description:   "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
		Regex:         gitlabOauthAppSecretRegex,
		Entropy:       3,
		Keywords:      []string{"gloas-"},
		Severity:      "High",
		Tags:          []string{TagSecretKey},
		Category:      CategorySourceCodeManagement,
		ScoreRuleType: 4,
	}
}
