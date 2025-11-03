package ruledefine

import (
	"regexp"
)

var gitlabPatRoutableRegex = regexp.MustCompile(`\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`).String()

func GitlabPatRoutable() *Rule {
	return &Rule{
		RuleID:          "56e9e4b5-5f1c-490b-9ae3-39b521b4103d",
		RuleName:        "Gitlab-Pat-Routable",
		Description:     "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.", //nolint:lll
		Regex:           gitlabPatRoutableRegex,
		Entropy:         4,
		Keywords:        []string{"glpat-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategorySourceCodeManagement, RuleType: 4},
	}
}
