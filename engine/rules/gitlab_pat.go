package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabPatRegex = regexp.MustCompile(`glpat-[\w-]{20}`)

func GitlabPat() *NewRule {
	return &NewRule{
		BaseRuleID:      "d641ed7c-e79f-4ce6-bbce-c5de97df7752",
		RuleID:          "gitlab-pat",
		Description:     "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
		Regex:           GitlabPatRegex,
		Entropy:         3,
		Keywords:        []string{"glpat-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
