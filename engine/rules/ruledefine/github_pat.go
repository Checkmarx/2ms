package ruledefine

import (
	"regexp"
)

var githubPATRegex = regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`).String()

func GitHubPat() *Rule {
	return &Rule{
		RuleID: "9f24ac30-9e04-4dc2-bc32-26da201f87e5",
		Description: "Uncovered a GitHub Personal Access Token," +
			" potentially leading to unauthorized repository access and sensitive content exposure.",
		RuleName: "Github-Pat",
		Regex:    githubPATRegex,
		Entropy:  3,
		Keywords: []string{"ghp_"},
		Severity: "High",
		AllowLists: []*AllowList{
			{
				Paths: []string{
					// https://github.com/octokit/auth-token.js/?tab=readme-ov-file#createtokenauthtoken-options
					regexp.MustCompile(`(?:^|/)@octokit/auth-token/README\.md$`).String(),
				},
			},
		},
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryDevelopmentPlatform, RuleType: 4},
	}
}
