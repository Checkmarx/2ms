package ruledefine

import (
	"regexp"
)

var gitlabPatRegex = regexp.MustCompile(`glpat-[\w-]{20}[\w-]*`).String()

var gitlabPatLongerTokenRegex = regexp.MustCompile(`^glpat-[\w-]{21}`).String()

func GitlabPat() *Rule {
	return &Rule{
		RuleID:      "d641ed7c-e79f-4ce6-bbce-c5de97df7752",
		RuleName:    "Gitlab-Pat",
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       gitlabPatRegex,
		Entropy:     3,
		Keywords:    []string{"glpat-"},
		AllowLists: []*AllowList{
			{
				Description: "Not a legacy PAT: longer than 20 chars after the prefix",
				RegexTarget: "match",
				Regexes:     []string{gitlabPatLongerTokenRegex},
			},
		},
		Severity:      "High",
		Tags:          []string{TagAccessToken},
		Category:      CategorySourceCodeManagement,
		ScoreRuleType: 4,
	}
}
