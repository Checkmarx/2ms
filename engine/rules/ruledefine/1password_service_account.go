package ruledefine

import (
	"regexp"
)

// regex for rule
var onePasswordServiceAccountTokenRegex = regexp.MustCompile(`ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}`).String()

func OnePasswordServiceAccountToken() *Rule {
	// define rule
	return &Rule{
		RuleID:        "0ea85582-ea27-4f6f-b5f0-db3c4a75a07e",
		RuleName:      "1Password-Service-Account-Token",
		Description:   "Uncovered a possible 1Password service account token, potentially compromising access to secrets in vaults.",
		Regex:         onePasswordServiceAccountTokenRegex,
		Entropy:       4,
		Keywords:      []string{"ops_"},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategoryAuthenticationAndAuthorization,
		ScoreRuleType: 4,
	}
}
