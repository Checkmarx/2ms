package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func PrivateKey() *config.Rule {
	// define rule
	return &config.Rule{
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		RuleID:      "private-key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S]*?KEY(?: BLOCK)?-----`),
		Keywords:    []string{"-----BEGIN"},
	}
}
