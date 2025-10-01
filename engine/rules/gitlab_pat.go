package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabPatRegex = regexp.MustCompile(`glpat-[\w-]{20}`)

func GitlabPat() *NewRule {
	return &NewRule{
		RuleID:      "gitlab-pat",
		Description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:       GitlabPatRegex,
		Entropy:     3,
		Keywords:    []string{"glpat-"},
	}
}
