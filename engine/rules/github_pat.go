package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GithubPATRegex = regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`)

func GitHubPat() *Rule {
	return &Rule{
		BaseRuleID: "9f24ac30-9e04-4dc2-bc32-26da201f87e5",
		Description: "Uncovered a GitHub Personal Access Token," +
			" potentially leading to unauthorized repository access and sensitive content exposure.",
		RuleID:   "github-pat",
		Regex:    GithubPATRegex,
		Entropy:  3,
		Keywords: []string{"ghp_"},
		Severity: "High",
		AllowLists: []*AllowList{
			{
				Paths: []*regexp.Regexp{
					// https://github.com/octokit/auth-token.js/?tab=readme-ov-file#createtokenauthtoken-options
					regexp.MustCompile(`(?:^|/)@octokit/auth-token/README\.md$`),
				},
			},
		},
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryDevelopmentPlatform, RuleType: 4},
	}
}
