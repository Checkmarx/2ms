package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GenericCredential() *config.Rule {
	regex := generateSemiGenericRegexIncludingXml([]string{
		"access",
		"auth",
		`(?-i:[Aa]pi|API)`,
		"credential",
		"creds",
		"key",
		"passw(?:or)?d",
		"secret",
		"token",
	}, `[\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3}`, true)

	return &config.Rule{
		RuleID:      "generic-api-key",
		Description: "Detected a Generic API Key, potentially exposing access to various services and sensitive operations.",
		Regex:       regex,
		Keywords: []string{
			"access",
			"api",
			"auth",
			"key",
			"credential",
			"creds",
			"passwd",
			"password",
			"secret",
			"token",
		},
		Entropy: 3.5,
		Allowlists: []*config.Allowlist{
			{
				StopWords: rules.DefaultStopWords,
			},
		},
	}
}
