package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GithubRefreshTokenRegex = regexp.MustCompile(`ghr_[0-9a-zA-Z]{36}`)

func GitHubRefresh() *NewRule {
	return &NewRule{
		BaseRuleID:      "711832c0-6aa8-46d1-ad44-2112e2771412",
		Description:     "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
		RuleID:          "github-refresh-token",
		Regex:           GithubRefreshTokenRegex,
		Entropy:         3,
		Keywords:        []string{"ghr_"},
		Severity:        "High",
		Tags:            []string{TagRefreshToken},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
