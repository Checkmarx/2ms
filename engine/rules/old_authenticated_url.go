package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func OldAuthenticatedURL() *config.Rule {
	regex := regexp.MustCompile(`://(\w+:\w\S+)@\S+\.\S+`)
	return &config.Rule{
		Description: "Identify username:password inside URLS",
		RuleID:      "authenticated-url",
		Regex:       regex,
		Keywords:    []string{"://"},
		SecretGroup: 1,
		Allowlists: []*config.Allowlist{
			{
				StopWords: []string{"password", "pass"},
			},
		},
	}
}
