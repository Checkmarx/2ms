package ruledefine

import (
	"regexp"
)

// This regex is the output regex of 'generic-api-key' rule from gitleaks, with the next changes:
// 1. gitleaks/gitleaks#1267
// 2. gitleaks/gitleaks#1265
// 3. Minimum length of 4 characters (was 10)
var hardcodedPasswordRegex = regexp.MustCompile(
	`(?i)(?:key|api|token|secret|client|passwd|password|auth|access)` +
		`(?:[0-9a-z\-_\t .]{0,20})(?:\s|'\s|"|\\){0,3}` +
		`(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)` +
		`(?:'|\"|\\|\s|=|\x60){0,5}([0-9a-z\-_.=!@#\$%\^\&\*]{4,150})` +
		`(?:['\"\\|\s\x60;<]|$)`,
).String()

func HardcodedPassword() *Rule {
	return &Rule{
		RuleID:      "df08858b-14b7-4aa6-a08f-2a7da30d4bc6",
		Description: "Hardcoded password",
		RuleName:    "Hardcoded-Password",
		Regex:       hardcodedPasswordRegex,
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
		AllowLists: []*AllowList{
			{
				StopWords: DefaultStopWords,
			},
		},
		Severity:        "High",
		Tags:            []string{TagPassword},
		ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
	}
}
