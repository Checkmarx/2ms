package rules

import (
	"regexp"

	"github.com/zricethezav/gitleaks/v8/config"
)

func OldPrivateKey() *config.Rule {
	return &config.Rule{
		RuleID:      "private-key",
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`), //nolint:gocritic,lll
		Keywords:    []string{"-----BEGIN"},
	}
}
