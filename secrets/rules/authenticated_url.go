package secrets

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func AuthenticatedURL() *config.Rule {
	regex, _ := regexp.Compile(`:\/\/(.+:.+)?@`)
	rule := config.Rule{
		Description: "Identify username:password inside URLS",
		RuleID:      "username-password-secret",
		Regex:       regex,
		Keywords:    []string{},
		SecretGroup: 1,
	}

	return &rule
}
