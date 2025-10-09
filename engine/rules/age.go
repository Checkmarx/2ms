package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

// regex for rule
var AgeSecretKeyRegex = regexp.MustCompile(`AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`)

func AgeSecretKey() *Rule {
	// define rule
	return &Rule{
		BaseRuleID: "5137d287-beb3-4ac4-844a-952618a69c47",
		Description: "Discovered a potential Age encryption tool secret key," +
			" risking data decryption and unauthorized access to sensitive information.",
		RuleID:          "age-secret-key",
		Regex:           AgeSecretKeyRegex,
		Keywords:        []string{"AGE-SECRET-KEY-1"},
		Severity:        "High",
		Tags:            []string{TagSecretKey},
		ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
	}
}
