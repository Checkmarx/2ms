package ruledefine

import (
	"regexp"
)

var AuthenticatedURLRegex = regexp.MustCompile(`://(\w+:\w\S+)@\S+\.\S+`)

func AuthenticatedURL() *Rule {
	return &Rule{
		BaseRuleID:  "98e88a4f-4b7d-4c56-a6fa-9835dfb7c8d7",
		Description: "Identify username:password inside URLS",
		RuleID:      "authenticated-url",
		Regex:       AuthenticatedURLRegex,
		Keywords:    []string{"://"},
		SecretGroup: 1,
		AllowLists: []*AllowList{
			{
				StopWords: []string{"password", "pass"},
			},
		},
		Severity:        "High",
		Tags:            []string{TagSensitiveUrl},
		ScoreParameters: ScoreParameters{Category: CategoryGeneralOrUnknown, RuleType: 4},
	}
}
