package ruledefine

import (
	"regexp"
)

var nugetConfigPasswordRegex = regexp.MustCompile(
	`(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`).String()

func NugetConfigPassword() *Rule {
	return &Rule{
		RuleID:      "9b6aa003-3d49-4b54-8f20-cee3eb9d0411",
		Description: "Identified a password within a Nuget config file, potentially compromising package management access.",
		RuleName:    "Nuget-Config-Password",
		Regex:       nugetConfigPasswordRegex,
		Entropy:     1,
		Keywords:    []string{"<add key="},
		Path:        regexp.MustCompile(`(?i)nuget\.config$`).String(),
		AllowLists: []*AllowList{
			{
				Regexes: []string{
					// samples from https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file
					regexp.MustCompile(`33f!!lloppa`).String(),
					regexp.MustCompile(`hal\+9ooo_da!sY`).String(),
					// exclude environment variables
					regexp.MustCompile(`^\%\S.*\%$`).String(), //nolint:gocritic
				},
			},
		},
		Severity:      "High",
		Tags:          []string{TagPassword},
		Category:      CategoryPackageManagement,
		ScoreRuleType: 4,
	}
}
