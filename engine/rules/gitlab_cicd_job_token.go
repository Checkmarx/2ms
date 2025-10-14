package rules

import (
	"regexp"
)

var GitlabCiCdJobTokenRegex = regexp.MustCompile(`glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`)

func GitlabCiCdJobToken() *Rule {
	return &Rule{
		BaseRuleID: "5282b318-f09a-4bba-b856-922b0151a795",
		RuleID:     "gitlab-cicd-job-token",
		Description: "Identified a GitLab CI/CD Job Token," +
			" potential access to projects and some APIs on behalf of a user while the CI job is running.",
		Regex:           GitlabCiCdJobTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glcbt-"},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
