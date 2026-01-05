package ruledefine

import (
	"regexp"
)

var githubRefreshTokenRegex = regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`).String()

func GitHubRefresh() *Rule {
	return &Rule{
		RuleID:        "711832c0-6aa8-46d1-ad44-2112e2771412",
		Description:   "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
		RuleName:      "Github-Refresh-Token",
		Regex:         githubRefreshTokenRegex,
		Entropy:       3,
		Keywords:      []string{"ghr_"},
		Severity:      "High",
		Tags:          []string{TagRefreshToken},
		Category:      CategoryAuthenticationAndAuthorization,
		ScoreRuleType: 4,
	}
}
