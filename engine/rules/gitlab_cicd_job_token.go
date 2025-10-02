package rules

import (
	"github.com/zricethezav/gitleaks/v8/regexp"
)

var GitlabCiCdJobTokenRegex = regexp.MustCompile(`glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`)

func GitlabCiCdJobToken() *NewRule {
	return &NewRule{
		RuleID:          "gitlab-cicd-job-token",
		Description:     "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
		Regex:           GitlabCiCdJobTokenRegex,
		Entropy:         3,
		Keywords:        []string{"glcbt-"},
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryCICD, RuleType: 4},
	}
}
