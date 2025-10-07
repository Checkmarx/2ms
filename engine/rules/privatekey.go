package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var PrivateKeyRegex = regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`) //nolint:gocritic,lll

func PrivateKey() *NewRule {
	return &NewRule{
		BaseRuleID:      "3fa46cbe-eeab-447a-90cf-790c27af3c0d",
		RuleID:          "private-key",
		Description:     "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		Regex:           PrivateKeyRegex,
		Keywords:        []string{"-----BEGIN"},
		Severity:        "High",
		Tags:            []string{TagPrivateKey},
		ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
	}
}
