package rules

import (
	"regexp"
)

var NugetConfigPasswordRegex = regexp.MustCompile(`(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`)

func NugetConfigPassword() *NewRule {
	return &NewRule{
		BaseRuleID:  "9b6aa003-3d49-4b54-8f20-cee3eb9d0411",
		Description: "Identified a password within a Nuget config file, potentially compromising package management access.",
		RuleID:      "nuget-config-password",
		Regex:       NugetConfigPasswordRegex,
		Entropy:     1,
		Keywords:    []string{"<add key="},
		Path:        regexp.MustCompile(`(?i)nuget\.config$`),
		AllowLists: []*AllowList{
			{
				Regexes: []*regexp.Regexp{
					// samples from https://learn.microsoft.com/en-us/nuget/reference/nuget-config-file
					regexp.MustCompile(`33f!!lloppa`),
					regexp.MustCompile(`hal\+9ooo_da!sY`),
					// exclude environment variables
					regexp.MustCompile(`^\%\S.*\%$`), //nolint:gocritic
				},
			},
		},
		Severity:        "High",
		Tags:            []string{TagPassword},
		ScoreParameters: ScoreParameters{Category: CategoryPackageManagement, RuleType: 4},
	}
}
