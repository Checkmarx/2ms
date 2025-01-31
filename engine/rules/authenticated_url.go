package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AuthenticatedURL() *config.Rule {
	regex, _ := regexp.Compile(`:\/\/(\w+:\w\S+)@\S+\.\S+`)
	rule := config.Rule{
		Description: "Identify username:password inside URLS",
		RuleID:      "authenticated-url",
		Regex:       regex,
		Keywords:    []string{"://"},
		SecretGroup: 1,
		Allowlist: config.Allowlist{
			StopWords: []string{"password", "pass"},
		},
	}

	return &rule
}
