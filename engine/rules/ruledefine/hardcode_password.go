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
)

func HardcodedPassword() *Rule {
	return &Rule{
		BaseRuleID:  "60b6a2aa-2eaf-4a3d-bd3c-6d5f6274b4fc",
		Description: "Hardcoded password",
		RuleID:      "hardcoded-password",
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
