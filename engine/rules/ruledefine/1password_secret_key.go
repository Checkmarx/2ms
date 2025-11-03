package ruledefine

import (
	"regexp"
)

// regex for rule
var onePasswordSecretKeyRegex = regexp.MustCompile(
	`\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b`).
	String()

func OnePasswordSecretKey() *Rule {
	// define rule
	return &Rule{
		RuleID:          "4068d686-6833-4976-8f4a-5397e75c7fc5",
		Description:     "Uncovered a possible 1Password secret key, potentially compromising access to secrets in vaults.",
		RuleName:        "1Password-Secret-Key",
		Regex:           onePasswordSecretKeyRegex,
		Entropy:         3.8,
		Keywords:        []string{"A3-"},
		Severity:        "High",
		Tags:            []string{TagPrivateKey},
		ScoreParameters: ScoreParameters{Category: CategoryAuthenticationAndAuthorization, RuleType: 4},
	}
}
