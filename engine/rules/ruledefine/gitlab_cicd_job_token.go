package ruledefine

import (
	"regexp"
)

var gitlabCiCdJobTokenRegex = regexp.MustCompile(`glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`).String()

func GitlabCiCdJobToken() *Rule {
	return &Rule{
		RuleID:   "5282b318-f09a-4bba-b856-922b0151a795",
		RuleName: "Gitlab-Cicd-Job-Token",
		Description: "Identified a GitLab CI/CD Job Token," +
			" potential access to projects and some APIs on behalf of a user while the CI job is running.",
		Regex:           gitlabCiCdJobTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glcbt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
