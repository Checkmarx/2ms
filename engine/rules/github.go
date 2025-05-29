package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GitHubApp() *config.Rule {
	// define rule
	r := config.Rule{
		Description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
		RuleID:      "github-app-token",
		Regex:       regexp.MustCompile(`ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}`),
		Keywords:    []string{"ghu_", "ghs_"},
	}

	// validate
	tps := []string{
		generateSampleSecret("github", "ghu_"+secrets.NewSecret(alphaNumeric("36"))),
		generateSampleSecret("github", "ghs_"+secrets.NewSecret(alphaNumeric("36"))),
	}
	return validate(r, tps, nil)
}
