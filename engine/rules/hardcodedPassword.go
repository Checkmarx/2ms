package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HardcodedPassword() *config.Rule {
	// This regex is the output regex of 'generic-api-key' rule from gitleaks, with the next changes:
	// 1. gitleaks/gitleaks#1267
	// 2. gitleaks/gitleaks#1265
	// 3. Minimum length of 4 characters (was 10)
	regex := regexp.MustCompile(
		`(?i)(?:key|api|token|secret|client|passwd|password|auth|access)` +
			`(?:[0-9a-z\-_\t .]{0,20})(?:\s|'\s|"|\\){0,3}` +
			`(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)` +
			`(?:'|\"|\\|\s|=|\x60){0,5}([0-9a-z\-_.=!@#\$%\^\&\*]{4,150})` +
			`(?:['\"\\|\s\x60;<]|$)`,
	)
	return &config.Rule{
		Description: "Hardcoded password",
		RuleID:      "hardcoded-password",
		Regex:       regex,
		Keywords: []string{
			"key",
			"api",
			"token",
			"secret",
			"client",
			"passwd",
			"password",
			"auth",
			"access",
		},
		Entropy:     0,
		SecretGroup: 1,
		Allowlists: []*config.Allowlist{
			{
				StopWords: rules.DefaultStopWords,
			},
		},
	}
}
