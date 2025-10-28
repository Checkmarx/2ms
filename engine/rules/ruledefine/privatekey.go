package ruledefine

import (
	"regexp"
)

var privateKeyRegex = regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`).String() //nolint:gocritic,lll

func PrivateKey() *Rule {
	return &Rule{
		RuleID:          "3fa46cbe-eeab-447a-90cf-790c27af3c0d",
		RuleName:        "private-key",
		Description:     "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		Regex:           privateKeyRegex,
		Keywords:        []string{"-----BEGIN"},
		Severity:        "High",
		Tags:            []string{TagPrivateKey},
		ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
	}
}
