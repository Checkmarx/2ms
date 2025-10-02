package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
)

var NpmAccessTokenRegex = utils.GenerateUniqueTokenRegex(`npm_[a-z0-9]{36}`, true)

func NPM() *NewRule {
	return &NewRule{
		BaseRuleID:  "c95ab734-0263-4b08-9366-1407667f32e2",
		Description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
		RuleID:      "npm-access-token",
		Regex:       NpmAccessTokenRegex,
		Entropy:     2,
		Keywords: []string{
			"npm_",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
