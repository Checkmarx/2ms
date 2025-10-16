package ruledefine

import (
	"regexp"
)

var githubOauthRegex = regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`)

func GitHubOauth() *Rule {
	return &Rule{
		BaseRuleID:      "0421c50a-7c92-472a-b074-f4df98d27e02",
		Description:     "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
		RuleID:          "github-oauth",
		Regex:           githubOauthRegex,
		Entropy:         3,
		Keywords:        []string{"gho_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
