package ruledefine

import (
	"regexp"
)

var authenticatedURLRegex = regexp.MustCompile(`://(\w+:\w\S+)@\S+\.\S+`).String()

func AuthenticatedURL() *Rule {
	return &Rule{
		RuleID:      "98e88a4f-4b7d-4c56-a6fa-9835dfb7c8d7",
		Description: "Identify username:password inside URLS",
		RuleName:    "Authenticated-Url",
		Regex:       authenticatedURLRegex,
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
