package rules

import (
	"regexp"
)

var GithubOauthRegex = regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`)

func GitHubOauth() *NewRule {
	return &NewRule{
		BaseRuleID:      "0421c50a-7c92-472a-b074-f4df98d27e02",
		Description:     "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
		RuleID:          "github-oauth",
		Regex:           GithubOauthRegex,
		Entropy:         3,
		Keywords:        []string{"gho_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
