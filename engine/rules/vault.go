package rules

import (
	"github.com/zricethezav/gitleaks/v8/config"
)

// Using this local version because newer versions of gitleaks have an entropy value, which was set as too high
// It's here as prevention in case a newer version of gitleaks starts getting used and causes issues on this rule
// If gitleaks is updated on 2ms and the new version of this rule has entropy, set it to 3.0
func VaultServiceToken() *config.Rule {
	// define rule
	return &config.Rule{
		Description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
		RuleID:      "vault-service-token",
		Regex:       generateUniqueTokenRegex(`hvs\.[a-z0-9_-]{90,100}`, true),
		Keywords:    []string{"hvs"},
	}
}
