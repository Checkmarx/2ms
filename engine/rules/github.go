package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func GitHubApp() *config.Rule {
	return &config.Rule{
		Description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		RuleID:      "github-app-token",
		Regex:       regexp.MustCompile(`(?:ghu|ghs)_[0-9a-zA-Z]{36}`),
		Keywords:    []string{"ghu_", "ghs_"},
	}
}
