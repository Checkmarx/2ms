package ruledefine

import (
	"regexp"
)

var githubAppTokenRegex = regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`).String()

func GitHubApp() *Rule {
	return &Rule{
		RuleID:          "388ebb1b-c894-430c-81fb-86d5037f44d3",
		Description:     "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		RuleName:        "Github-App-Token",
		Regex:           githubAppTokenRegex,
		Entropy:         3,
		Keywords:        []string{"ghu_", "ghs_"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
